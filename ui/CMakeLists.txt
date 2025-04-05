cmake_minimum_required(VERSION 3.5)

# Project name
project(MyQtApp)

# Set the required Qt version
find_package(Qt5 REQUIRED COMPONENTS Core Gui Widgets)

# Add executable
add_executable(gui gui.cpp)

# Link Qt5 libraries to the executable
target_link_libraries(gui Qt5::Core Qt5::Gui Qt5::Widgets)

