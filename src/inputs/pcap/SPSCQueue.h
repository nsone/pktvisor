/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

// Copyright (c) 2025 NSONE, Inc. All rights reserved.

#pragma once

#include <atomic>
#include <cassert>
#include <cstddef>
#include <memory>

namespace visor::input::pcap {

/**
 * Single-producer / single-consumer lock-free ring queue.
 *
 * Capacity must be a power of two. T must be moveable.
 * try_push() is called by the producer only; try_pop() by the consumer only.
 * Both operations are wait-free.
 */
template <typename T>
class SPSCQueue
{
public:
    explicit SPSCQueue(size_t capacity)
        : _cap(capacity)
        , _buf(std::make_unique<T[]>(capacity))
        , _head(0)
        , _tail(0)
    {
        assert(capacity >= 2 && (capacity & (capacity - 1)) == 0
            && "capacity must be a power of two and >= 2");
    }

    // Attempt to enqueue by move. Returns false when the queue is full.
    bool try_push(T &&item)
    {
        const size_t head = _head.load(std::memory_order_relaxed);
        const size_t next = (head + 1) % _cap;
        if (next == _tail.load(std::memory_order_acquire)) {
            return false; // full
        }
        _buf[head] = std::move(item);
        _head.store(next, std::memory_order_release);
        return true;
    }

    // Attempt to dequeue by move. Returns false when the queue is empty.
    bool try_pop(T &item)
    {
        const size_t tail = _tail.load(std::memory_order_relaxed);
        if (tail == _head.load(std::memory_order_acquire)) {
            return false; // empty
        }
        item = std::move(_buf[tail]);
        _tail.store((tail + 1) % _cap, std::memory_order_release);
        return true;
    }

    size_t capacity() const { return _cap; }

private:
    const size_t _cap;
    std::unique_ptr<T[]> _buf;

    // Keep producer and consumer indices on separate cache lines to avoid
    // false sharing.
    alignas(64) std::atomic<size_t> _head;
    alignas(64) std::atomic<size_t> _tail;
};

} // namespace visor::input::pcap
