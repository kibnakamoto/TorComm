cmake_minimum_required(VERSION 3.5)

# TODO: update required components (find_package) and target_link_libraries

# Project name
project(TorComm)

# Set the required Qt version
find_package(Qt5 REQUIRED COMPONENTS Core Gui Widgets)

# automatic moc to avoid linker error (since using Q_Object for private slots, this command is needed as moc file is needed)
set(CMAKE_AUTOMOC ON)

# Add executable
add_executable(gui gui.cpp gui.h)

# Link Qt5 libraries to the executable
target_link_libraries(gui Qt5::Core Qt5::Gui Qt5::Widgets)

set(CMAKE_CXX_FLAGS_DEBUG   "-std=c++2b -Wall -pedantic -Wextra -O4 -fcoroutines -g")
set(CMAKE_CXX_FLAGS_RELEASE "-std=c++2b -Wall -pedantic -Wextra -O4 -fcoroutines")
