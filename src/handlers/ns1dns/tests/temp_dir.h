#pragma once

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>

/**
 * RAII class to create and delete a temporary directory.
 */
class temporary_dir
{
    std::string _path;

public:
    temporary_dir() = default;

    temporary_dir(std::string _template)
    {
        std::string path = std::filesystem::temp_directory_path() / _template;
        if (mkdtemp(path.data()) == nullptr) {
            throw std::system_error(errno, std::generic_category());
        }

        _path = path;
    }

    // non-copyable
    temporary_dir(const temporary_dir &) = delete;
    temporary_dir &operator=(const temporary_dir &) = delete;

    temporary_dir(temporary_dir &&other)
    {
        std::swap(_path, other._path);
    }

    temporary_dir &operator=(temporary_dir &&other)
    {
        std::swap(_path, other._path);
        return *this;
    }

    ~temporary_dir()
    {
        if (!_path.empty()) {
            std::error_code ec;
            std::filesystem::remove_all(_path, ec);
        }
    }

    const std::string &path() const
    {
        return _path;
    }
};

