#ifndef _BITS_STAT_H
#define _BITS_STAT_H

#define S_ISDIR(mode) mode & S_IFMT == S_IFDIR
#define S_ISCHR(mode) mode & S_IFMT == S_IFCHR
#define S_ISBLK(mode) mode & S_IFMT == S_IFBLK
#define S_ISREG(mode) mode & S_IFMT == S_IFREG
#define S_ISIFO(mode) mode & S_IFMT == S_IFIFO
#define S_ISLNK(mode) mode & S_IFMT == S_IFLNK

#define st_atime st_atim.tv_sec
#define st_mtime st_mtim.tv_sec

#endif
