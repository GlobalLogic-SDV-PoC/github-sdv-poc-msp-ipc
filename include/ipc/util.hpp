#pragma once
#include <functional>
#include <tuple>

namespace ipc
{
template <typename Callable, typename... Args>
auto bind_front(Callable&& callable, Args&&... front_args)
{
    return [_callable = std::forward<Callable>(callable),
            _front_args = std::make_tuple(std::forward<Args>(front_args)...)](auto&&... args) -> decltype(auto)
    {
        return std::apply(_callable, std::tuple_cat(_front_args, std::forward_as_tuple(std::forward<decltype(args)>(args)...)));
    };
}

template <typename Callable, typename... Args>
auto bind_back(Callable&& callable, Args&&... back_args)
{
    return [callable = std::forward<Callable>(callable),
            back_args_tuple = std::make_tuple(std::forward<Args>(back_args)...)](auto&&... args) -> decltype(auto)
    {
        return std::apply(callable, std::tuple_cat(std::forward_as_tuple(std::forward<decltype(args)>(args)...), back_args_tuple));
    };
}
}  // namespace ipc