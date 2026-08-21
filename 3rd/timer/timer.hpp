#pragma once

#include <list>
#include <mutex>
#include <tuple>
#include <thread>
#include <chrono>
#include <memory>
#include <iterator>
#include <stdexcept>
#include <functional>
#include <cstdint>
#include <condition_variable>
#include <deque>
#include <vector>
#include "event.hpp"

// ---------------------------------------------------------------------------
// Simple fixed-size thread pool used by timer to dispatch due callbacks off
// the tick thread, so m_events_lock is held only for iteration, not execution.
// ---------------------------------------------------------------------------
class timer_thread_pool
{
public:
	explicit timer_thread_pool(std::size_t n_threads)
	{
		for (std::size_t i = 0; i < n_threads; ++i) {
			m_threads.emplace_back([this] { worker(); });
		}
	}

	~timer_thread_pool()
	{
		{
			std::unique_lock lock(m_mutex);
			m_stop = true;
		}
		m_cv.notify_all();
		for (auto &t : m_threads) {
			t.join();
		}
	}

	void post(std::function<void()> task)
	{
		{
			std::unique_lock lock(m_mutex);
			m_queue.push_back(std::move(task));
		}
		m_cv.notify_one();
	}

private:
	void worker()
	{
		for (;;) {
			std::function<void()> task;
			{
				std::unique_lock lock(m_mutex);
				m_cv.wait(lock, [this] { return m_stop || !m_queue.empty(); });
				if (m_stop && m_queue.empty()) {
					return;
				}
				task = std::move(m_queue.front());
				m_queue.pop_front();
			}
			task();
		}
	}

	std::vector<std::thread> m_threads;
	std::deque<std::function<void()>> m_queue;
	std::mutex m_mutex;
	std::condition_variable m_cv;
	bool m_stop{false};
};

class timer
{
public:
	// Number of worker threads used to dispatch due callbacks.
	// 4 threads is enough to keep the tick thread free at high policy counts
	// while avoiding excessive context switching.
	static constexpr std::size_t POOL_THREADS = 4;

	template<typename R, typename P>
	explicit timer(const std::chrono::duration<R, P>& tick)
	: m_tick{ std::chrono::duration_cast<std::chrono::nanoseconds>(tick) }
	, m_pool{ POOL_THREADS }
	{
		if(m_tick.count() <= 0)
		{
			throw std::invalid_argument("Invalid tick value: must be greater than zero!");
		}

		m_tick_thread = std::make_unique<std::thread>([this]()
		{
			auto start = std::chrono::steady_clock::now();

			while(!m_tick_event.wait_until(start + m_tick * ++m_ticks))
			{
				// Collect due events while holding the lock, then dispatch them
				// to the pool without holding the lock.  This keeps the lock
				// hold time O(N) in list traversal only, not in callback cost.
				std::vector<event_ctx_ptr> due;
				std::vector<event_ctx_ptr> to_remove;

				{
					std::scoped_lock lock{ m_events_lock };

					auto it = std::begin(m_events);
					auto end = std::end(m_events);

					while(it != end)
					{
						auto& e = *it;

						if(e->elapsed += m_tick.count(); e->elapsed >= e->ticks)
						{
							// Check cancellation under the lock before queuing.
							if(e->cancelled->wait_for(std::chrono::seconds{0}))
							{
								// Already cancelled — remove from list.
								it = m_events.erase(it);
								continue;
							}
							e->elapsed = 0;
							due.push_back(e);
							if (e->one_shot) {
								it = m_events.erase(it);
								continue;
							}
						}

						++it;
					}
				}

				// Dispatch each due callback to the pool.
				for (auto& e : due) {
					m_pool.post([e]() mutable {
						// Re-check cancellation in the pool thread.
						if(e->cancelled->wait_for(std::chrono::seconds{0}))
						{
							return;
						}
						auto remove = e->proc();
						(void)remove; // removal is handled in tick thread
						e->signal_work();
					});
				}
			}
		});
	}

	~timer()
	{
		m_tick_event.signal();
		m_tick_thread->join();
		// pool destructor joins workers
	}

	using manual_event_ptr = std::shared_ptr<manual_event>;
	using auto_event_ptr = std::shared_ptr<auto_event>;

	template<typename C, typename W>
	struct event_handle
	{
		event_handle(C cancel_event, W work_event)
		: m_cancel_event{ cancel_event }, m_work_event{ work_event } {}

		void cancel() { m_cancel_event->signal(); }

		void wait() { m_work_event->wait(); }

		template<typename Rep, typename Period>
		bool wait_for(const std::chrono::duration<Rep, Period>& t) { return m_work_event->wait_for(t); }

		template<typename Clock, typename Duration>
		bool wait_until(const std::chrono::time_point<Clock, Duration>& t) { return m_work_event->wait_until(t); }

	private:
		C m_cancel_event;
		W m_work_event;
	};

	using timeout_handle = event_handle<manual_event_ptr, manual_event_ptr>;
	using interval_handle = event_handle<manual_event_ptr, auto_event_ptr>;

	template<typename R, typename P, typename F, typename... Args>
	[[nodiscard]] auto set_timeout(const std::chrono::duration<R, P>& timeout, F&& f, Args&&... args)
	{
		if(timeout.count() <= 0)
		{
			throw std::invalid_argument("Invalid timeout value: must be greater than zero!");
		}

		auto cancel_event = std::make_shared<manual_event>();
		auto work_event = std::make_shared<manual_event>();
		auto handle = std::make_shared<timeout_handle>(cancel_event, work_event);

		auto ctx = std::make_shared<event_ctx>(
			std::chrono::duration_cast<std::chrono::nanoseconds>(timeout).count(),
			/*one_shot=*/true,
			cancel_event,
			[=]{ work_event->signal(); },
			[p = std::forward<F>(f), t = std::make_tuple(std::forward<Args>(args)...)]() mutable
			{
				std::apply(p, t);
				return true;
			});

		{
			std::scoped_lock lock{ m_events_lock };
			m_events.push_back(ctx);
		}

		return handle;
	}

	template<typename R, typename P, typename F, typename... Args>
	[[nodiscard]] auto set_interval(const std::chrono::duration<R, P>& interval, F&& f, Args&&... args)
	{
		if(interval.count() <= 0)
		{
			throw std::invalid_argument("Invalid interval value: must be greater than zero!");
		}

		auto cancel_event = std::make_shared<manual_event>();
		auto work_event = std::make_shared<auto_event>();
		auto handle = std::make_shared<interval_handle>(cancel_event, work_event);

		auto ctx = std::make_shared<event_ctx>(
			std::chrono::duration_cast<std::chrono::nanoseconds>(interval).count(),
			/*one_shot=*/false,
			cancel_event,
			[=]{ work_event->signal(); },
			[p = std::forward<F>(f), t = std::make_tuple(std::forward<Args>(args)...)]() mutable
			{
				std::apply(p, t);
				return false;
			});

		{
			std::scoped_lock lock{ m_events_lock };
			m_events.push_back(ctx);
		}

		return handle;
	}

private:
	std::chrono::nanoseconds m_tick;
	std::uint64_t m_ticks = 0;

	using thread_ptr = std::unique_ptr<std::thread>;
	thread_ptr m_tick_thread;
	manual_event m_tick_event;
	timer_thread_pool m_pool;

	struct event_ctx
	{
		using proc_t = std::function<bool(void)>;

		event_ctx(std::uint64_t t, bool one_shot_,
		          std::shared_ptr<manual_event> cancelled_,
		          std::function<void()> signal_work_,
		          proc_t&& p)
		: ticks{ t }
		, one_shot{ one_shot_ }
		, cancelled{ std::move(cancelled_) }
		, signal_work{ std::move(signal_work_) }
		, proc{ std::move(p) }
		{}

		std::uint64_t ticks;
		std::uint64_t elapsed = 0;
		bool one_shot;
		std::shared_ptr<manual_event> cancelled;
		// Called by the pool worker after proc() completes to unblock wait_for().
		std::function<void()> signal_work;
		proc_t proc;
	};

	using event_ctx_ptr = std::shared_ptr<event_ctx>;
	using event_list = std::list<event_ctx_ptr>;
	event_list m_events;
	std::recursive_mutex m_events_lock;
};
