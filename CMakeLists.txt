cmake_minimum_required(VERSION 3.15)
project(router)

set(CMAKE_CXX_STANDARD 14)

include_directories(include)

add_executable(router
        include/list.h
        include/queue.h
        include/skel.h
        check.sh
        checker.py
        info.py
        list.c
        Makefile
        queue.c
        router.c
        rtable.txt
        skel.c
        tests.py
        topo.py include/arp.h include/route_table.h include/arp_table.h include/ip.h)
