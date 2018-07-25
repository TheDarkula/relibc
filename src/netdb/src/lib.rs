//! netdb implementation for Redox, following http://pubs.opengroup.org/onlinepubs/7908799/xsh/netdb.h.html

#![no_std]

#![feature(alloc)]

#[macro_use]
extern crate alloc;

extern crate arpainet;
extern crate errno;
extern crate fcntl;
extern crate platform;
extern crate stdlib;
extern crate string;
extern crate sys_socket;
extern crate netinet;
extern crate time;

mod dns;

use core::{mem, str, ptr};

use alloc::{Vec, String};
use alloc::str::SplitWhitespace;
use alloc::string::ToString;
use alloc::vec::IntoIter;
use alloc::boxed::Box;

use arpainet::{htons, inet_aton};

use errno::*;

use fcntl::O_RDONLY;

use platform::types::*;
use platform::rlb::RawLineBuffer;
use platform::rawfile::file_read_all;
use platform::{c_str, open, cstr_from_bytes_with_nul_unchecked, SEEK_SET};

use dns::{Dns, DnsQuery};

use netinet::in_h::{in_addr, IPPROTO_UDP, sockaddr_in};

use stdlib::atoi;

use string::{strcmp};

use sys_socket::{sockaddr, socklen_t};
use sys_socket::constants::{SOCK_DGRAM, AF_INET};

const MAXADDRS: usize = 35;
const MAXALIASES: usize = 35;

struct LookupHost(IntoIter<in_addr>);

impl Iterator for LookupHost {
    type Item = in_addr;
    fn next (&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

#[repr(C)]
pub struct hostent {
    h_name: *const c_char,
    h_aliases: *const *const c_char,
    h_addrtype: c_int,
    h_length: c_int,
    h_addr_list: *const *const c_char,
}

#[repr(C)]
pub struct netent {
    n_name: *const c_char, /* official name of net */
    n_aliases: *const *const c_char, /* alias list */
    n_addrtype: c_int, /* net address type */
    n_net: c_ulong, /* network # */
}

#[repr(C)]
pub struct servent {
    s_name: *const c_char, /* official service name */
    s_aliases: *const *const c_char, /* alias list */
    s_port: c_int, /* port # */
    s_proto: *const c_char, /* protocol to use */
}

#[repr(C)]
pub struct protoent {
    p_name: *const c_char, /* official protocol name */
    p_aliases: *const *const c_char, /* alias list */
    p_proto: c_int, /* protocol # */
}

#[repr(C)]
pub struct addrinfo {
    ai_flags: c_int, /* AI_PASSIVE, AI_CANONNAME, AI_NUMERICHOST */
    ai_family: c_int, /* PF_xxx */
    ai_socktype: c_int, /* SOCK_xxx */
    ai_protocol: c_int, /* 0 or IPPROTO_xxx for IPv4 and IPv6 */
    ai_addrlen: size_t, /* length of ai_addr */
    ai_canonname: *const c_char, /* canonical name for hostname */
    ai_addr: *const sockaddr, /* binary address */
    ai_next: *const addrinfo, /* next structure in linked list */
}

static mut NETDB: c_int = 0;
static mut NET_ENTRY: netent = netent {
    n_name: 0 as *const c_char,
    n_aliases: 0 as *const *const c_char,
    n_addrtype: 0,
    n_net: 0 as u64,
};
static mut NET_NAME: Option<Vec<u8>> = None;
static mut NET_ALIASES: [*const c_char; MAXALIASES] = [ptr::null(); MAXALIASES];
static mut NET_NUM: Option<u64> = None;
static mut N_LINE: RawLineBuffer = RawLineBuffer {
    fd: 0,
    cur: 0,
    read: 0,
    buf: [0; 8 * 1024],
};
static mut NET_STAYOPEN: c_int = 0;

static mut HOSTDB: c_int = 0;
static mut HOST_ENTRY: hostent = hostent {
    h_name: 0 as *const c_char,
    h_aliases: 0 as *const *const c_char,
    h_addrtype: 0,
    h_length: 0,
    h_addr_list: 0 as *const *const c_char,
};
static mut HOST_NAME: Option<Vec<u8>> = None;
static mut HOST_ALIASES: Option<Vec<Vec<u8>>> = None; 
static mut HOST_ADDR: Option<in_addr> = None;
static mut HOST_ADDR_LIST: [*const c_char; 2] = [ptr::null(); 2];
static mut H_LINE: RawLineBuffer = RawLineBuffer {
    fd: 0,
    cur: 0,
    read: 0,
    buf: [0; 8 * 1024],
};
static mut HOST_STAYOPEN: c_int = 0;

static mut PROTODB: c_int = 0;
static mut PROTO_ENTRY: protoent = protoent {
    p_name: 0 as *const c_char,
    p_aliases: 0 as *const *const c_char,
    p_proto: 0 as c_int,
};
static mut PROTO_NAME: Option<Vec<u8>> = None;
static mut PROTO_ALIASES: Option<Vec<Vec<u8>>> = None;
static mut PROTO_NUM: Option<c_int> = None;
static mut P_LINE: RawLineBuffer = RawLineBuffer {
    fd: 0,
    cur: 0,
    read: 0,
    buf: [0; 8 * 1024],
};
static mut PROTO_STAYOPEN: c_int = 0;

static mut SERVDB: c_int = 0;
static mut SERV_ENTRY: servent = servent {
    s_name: 0 as *const c_char,
    s_aliases: 0 as *const *const c_char,
    s_port: 0 as c_int,
    s_proto: 0 as *const c_char,
};
static mut SERV_NAME: Option<Vec<u8>> = None;
static mut SERV_ALIASES: Option<Vec<Vec<u8>>> = None;
static mut SERV_PORT: Option<c_int> = None;
static mut SERV_PROTO: Option<Vec<u8>> = None;
static mut S_LINE: RawLineBuffer = RawLineBuffer {
    fd: 0,
    cur: 0,
    read: 0,
    buf: [0; 8 * 1024],
};
static mut SERV_STAYOPEN: c_int = 0;

fn lookup_host(host: &str) -> Result<LookupHost, ()> {
    let mut dns_string: String = String::new();
    #[cfg(target_os = "redox")] {
         dns_string = String::from_utf8(file_read_all("/etc/net/dns")?).or(Err(()))?; 
    }
    #[cfg(target_os = "linux")] {
        let fd = platform::open(b"/etc/resolv.conf\0".as_ptr() as *const i8, O_RDONLY, 0);
        let mut rlb = RawLineBuffer::new(fd);
        for line in rlb.next() {
            let line = String::from(line); 
            if line.starts_with("nameserver") {
                dns_string = line.trim_left_matches("nameserver ").to_string();
            }
        }
    }

    let dns_vec: Vec<u8> = dns_string
        .trim()
        .split(".")
        .map(|octet| octet.parse::<u8>().unwrap_or(0))
        .collect();

    let mut dns_arr =  [0u8;4];

    for (i, octet) in dns_vec.iter().enumerate() {
        dns_arr[i] = *octet;
    }

    if dns_vec.len() == 4 {
        let mut timespec = timespec::default();
        platform::clock_gettime(time::constants::CLOCK_REALTIME, &mut timespec);
        let tid = (timespec.tv_nsec >> 16) as u16;

        let packet = Dns {
            transaction_id: tid,
            flags: 0x0100,
            queries: vec![
                DnsQuery {
                    name: host.to_string(),
                    q_type: 0x0001,
                    q_class: 0x0001,
                },
            ],
            answers: vec![],
        };

        let packet_data = packet.compile();
        let packet_data_ptr = &packet_data as *const _ as *const c_void;
        
        let sock = unsafe {sys_socket::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP as i32)};

        let mut dest = sockaddr_in {
            sa_family: AF_INET as u16,
            sin_port: htons(53), 
            sin_addr: in_addr {
                s_addr: unsafe { mem::transmute::<[u8;4], u32>(dns_arr) },
            },
        };

        let dest_ptr = &mut dest as *mut _ as *mut sockaddr;
        
        unsafe {
            if sys_socket::sendto(sock, packet_data_ptr, packet_data.len(), 0, dest_ptr, 4) < 0 {
                return Err(());
            }
        }

        let mut i = mem::size_of::<sockaddr_in>() as socklen_t;
        let mut buf = [0u8;65536];
        let buf_ptr = buf.as_mut_ptr() as *mut c_void;

        let mut count = -1;

        unsafe {
            count = sys_socket::recvfrom(sock, buf_ptr, 65536, 0, dest_ptr, &mut i as *mut socklen_t);
        }
        if count < 0 {
            return Err(())
        }
        
        match Dns::parse(&buf[..count as usize]) {
            Ok(response) => {
                let mut addrs = vec![];
                for answer in response.answers.iter() {
                    if answer.a_type == 0x0001 && answer.a_class == 0x0001 &&
                        answer.data.len() == 4
                    {
                        let addr = in_addr {
                            s_addr: unsafe { mem::transmute::<[u8;4], u32>([
                                answer.data[0],
                                answer.data[1],
                                answer.data[2],
                                answer.data[3],
                            ])},
                        };
                        addrs.push(addr);
                    }
                }
                Ok(LookupHost(addrs.into_iter()))
            }
            Err(_err) => Err(()),
        }
    } else {
        Err(())
    }
}

fn lookup_addr(addr: in_addr) -> Result<Vec<Vec<u8>>, ()> {
    let mut dns_string: String = String::new();
    #[cfg(target_os = "redox")] {
         dns_string = String::from_utf8(file_read_all("/etc/net/dns")?).or(Err(()))?; 
    }
    #[cfg(target_os = "linux")] {
        let fd = platform::open(b"/etc/resolv.conf".as_ptr() as *const i8, O_RDONLY, 0);
        let mut rlb = RawLineBuffer::new(fd);
        for line in rlb.next() {
            let line = String::from(line); 
            if line.starts_with("nameserver") {
                dns_string = line.trim_left_matches("nameserver ").to_string();
            }
        }
    }

    let dns_vec: Vec<u8> = dns_string
        .trim()
        .split(".")
        .map(|octet| octet.parse::<u8>().unwrap_or(0))
        .collect();

    let mut dns_arr =  [0u8;4];

    for (i, octet) in dns_vec.iter().enumerate() {
        dns_arr[i] = *octet;
    }

    let mut addr_vec: Vec<u8> = unsafe { mem::transmute::<u32, [u8;4]>(addr.s_addr).to_vec() };
    addr_vec.reverse();
    let mut name: Vec<u8> = vec![];
    for octet in addr_vec {
        for ch in format!("{}", octet).as_bytes() {
            name.push(*ch);
        }
        name.push(b"."[0]);
    }
    name.pop();
    for ch in b".IN-ADDR.ARPA" {
        name.push(*ch);
    }

    if dns_vec.len() == 4 {
        let mut timespec = timespec::default();
        platform::clock_gettime(time::constants::CLOCK_REALTIME, &mut timespec);
        let tid = (timespec.tv_nsec >> 16) as u16;

        let packet = Dns {
            transaction_id: tid,
            flags: 0x0100,
            queries: vec![
                DnsQuery {
                    name: String::from_utf8(name).unwrap(), 
                    q_type: 0x000C,
                    q_class: 0x0001,
                },
            ],
            answers: vec![],
        };

        let packet_data = packet.compile();
        let packet_data_ptr = &packet_data as *const _ as *const c_void;
        
        let sock = unsafe {sys_socket::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP as i32)};

        let mut dest = sockaddr_in {
            sa_family: AF_INET as u16,
            sin_port: 53, // may need to htons this
            sin_addr: in_addr {
                s_addr: unsafe { mem::transmute::<[u8;4], u32>(dns_arr) },
            },
        };

        let dest_ptr = &mut dest as *mut _ as *mut sockaddr;
        
        unsafe {
            if sys_socket::sendto(sock, packet_data_ptr, packet_data.len(), 0, dest_ptr, 4) < 0 {
                return Err(());
            }
        }

        let mut i = mem::size_of::<sockaddr_in>() as socklen_t;
        let mut buf = [0u8;65536];
        let buf_ptr = buf.as_mut_ptr() as *mut c_void;

        let mut count = -1;

        unsafe {
            count = sys_socket::recvfrom(sock, buf_ptr, 65536, 0, dest_ptr, &mut i as *mut socklen_t);
        }
        if count < 0 {
            return Err(())
        }
        
        match Dns::parse(&buf[..count as usize]) {
            Ok(response) => {
                let mut names = vec![];
                for answer in response.answers.iter() {
                    if answer.a_type == 0x000C && answer.a_class == 0x0001 {
                        // answer.data is encoded kinda weird.
                        // Basically length-prefixed strings for each 
                        // subsection of the domain. 
                        // We need to parse this to insert periods where
                        // they belong (ie at the end of each string)
                        let data = parse_revdns_answer(answer.data.clone());
                        names.push(data);
                    }
                }
                Ok(names)
            }
            Err(_err) => Err(()),
        }
    } else {
        Err(())
    }
}

fn parse_revdns_answer(data: Vec<u8>) -> Vec<u8> {
    let mut cursor = 0;
    let mut offset = 0;
    let mut index = 0; 
    let mut output = data.clone();
    while index < data.len() - 1 {
        offset = data[index] as usize;
        index = cursor + offset + 1;
        output[index] = '.' as u8;
        cursor = index;
    }
    //we don't want an extra period at the end
    output.pop(); 
    output 
}

pub unsafe extern "C" fn endhostent() {
    platform::close(HOSTDB);
}

pub unsafe extern "C" fn endnetent() {
    platform::close(NETDB);
}

pub unsafe extern "C" fn endprotoent() {
    platform::close(PROTODB);
}

pub unsafe extern "C" fn endservent() {
    platform::close(SERVDB);
}

//TODO read hosts file
pub unsafe extern "C" fn gethostbyaddr(v: *const c_void, length: socklen_t, format:c_int) -> *const hostent {
    let mut addr: in_addr = *(v as *mut in_addr);
    match lookup_addr(addr) {
        Ok(s) => {
            HOST_ADDR_LIST = [
                mem::transmute::<u32, [u8;4]>(addr.s_addr)
                    .as_ptr() as *const c_char, ptr::null()
            ];
            let host_name = s[0].to_vec();
            HOST_ENTRY = hostent {
                h_name: host_name.as_ptr() as *const c_char,
                h_aliases: [ptr::null();2].as_ptr(), //TODO actually get aliases
                h_addrtype: format,
                h_length: length as i32,
                h_addr_list: HOST_ADDR_LIST.as_ptr()
            };
            HOST_NAME = Some(host_name);
            &HOST_ENTRY
        }
        Err(()) => ptr::null()
    }
}

//TODO Read hosts file
pub unsafe extern "C" fn gethostbyname(name: *const c_char) -> *const hostent {
    // XXX h_errno
    let mut addr = mem::uninitialized();
    let mut host_addr = if inet_aton(name, &mut addr) == 1 {
        addr
    } else {
        // XXX
        let mut host = lookup_host(str::from_utf8_unchecked(c_str(name))).unwrap();
        host.next().ok_or( { platform::errno = ENOENT; return ptr::null() });
    };

    let host_name: Vec<u8> = c_str(name).to_vec();
    HOST_ADDR_LIST = [&host_addr.s_addr as *const _ as *const c_char, ptr::null()];
    HOST_ADDR = Some(host_addr);

    HOST_ENTRY = hostent {
        h_name: host_name.as_ptr() as *const c_char,
        h_aliases: [ptr::null();2].as_ptr(),
        h_addrtype: AF_INET,
        h_length: 4,
        h_addr_list: HOST_ADDR_LIST.as_ptr()
    };

    HOST_NAME = Some(host_name);
    &HOST_ENTRY as *const hostent
}

pub unsafe extern "C" fn gethostent() -> *const hostent {
    if HOSTDB == 0 {
        HOSTDB = open(cstr_from_bytes_with_nul_unchecked(b"/etc/hosts\0"), O_RDONLY, 0);
        H_LINE = RawLineBuffer::new(HOSTDB);
    }

    let mut r: Box<str> = Box::default();
    while r.is_empty() || r.split_whitespace().next() == None || r.starts_with("#") {
        r = match H_LINE.next() {
            Some(s) => s,
            None => {
                if HOST_STAYOPEN == 0 { endhostent(); }
                return ptr::null();
            }
        };
    }
    
    let mut iter: SplitWhitespace = r.split_whitespace();
    
    let mut addr_vec = iter.next().unwrap().as_bytes().to_vec();
    addr_vec.push(b'\0');
    let addr_cstr = addr_vec.as_slice().as_ptr() as *const i8;
    let mut addr = mem::uninitialized();
    inet_aton(addr_cstr, &mut addr);
    HOST_ADDR_LIST = [&addr.s_addr as *const _ as *const c_char, ptr::null()];
    HOST_ADDR = Some(addr);

    let mut host_name = iter.next().unwrap().as_bytes().to_vec();
    host_name.push(b'\0');
    
    let mut host_aliases: Vec<Vec<u8>> = Vec::new(); 
    
    loop {
        let mut alias = match iter.next() {
            Some(s) => s.as_bytes().to_vec(),
            None => break
        };
        alias.push(b'\0');
        host_aliases.push(alias);
    }

    host_aliases.push(vec![b'\0']);

    HOST_ENTRY = hostent { 
        h_name: host_name.as_ptr() as *const c_char,
        h_aliases: host_aliases.as_slice().as_ptr() as *const *const i8,
        h_addrtype: AF_INET, 
        h_length: 4,
        h_addr_list: HOST_ADDR_LIST.as_ptr()
    };
        HOST_ALIASES = Some(host_aliases);
        HOST_NAME = Some(host_name); 
        &HOST_ENTRY as *const hostent
}

pub unsafe extern "C" fn getnetbyaddr(net: u32, net_type: c_int) -> *const netent {
    unimplemented!();
}

pub unsafe extern "C" fn getnetbyname(name: *const c_char) -> *const netent {
    unimplemented!();
}

pub unsafe extern "C" fn getnetent() -> *const netent {
    unimplemented!();
}

pub unsafe extern "C" fn getprotoent() -> *const protoent {
    if PROTODB == 0 {
        PROTODB = open(cstr_from_bytes_with_nul_unchecked(b"/etc/protocols\0"), O_RDONLY, 0);
        P_LINE = RawLineBuffer::new(PROTODB);
    }

    let mut r: Box<str> = Box::default();
    while r.is_empty() || r.split_whitespace().next() == None || r.starts_with("#") {
        r = match P_LINE.next() {
            Some(s) => s,
            None => {
                if PROTO_STAYOPEN == 0 { endprotoent(); } 
                return ptr::null();
            },
        };
    }
    
    let mut iter: SplitWhitespace = r.split_whitespace();

    let mut proto_name: Vec<u8> = iter.next().unwrap().as_bytes().to_vec(); 
    proto_name.push(b'\0');
    
    let mut num = iter.next().unwrap().as_bytes().to_vec();
    num.push(b'\0');
    PROTO_NUM = Some(atoi(num.as_slice().as_ptr() as *mut i8)); 

    let mut proto_aliases: Vec<Vec<u8>> = Vec::new(); 
    loop {
        let mut alias = match iter.next() {
            Some(s) => s.as_bytes().to_vec(),
            None => break
        };
        alias.push(b'\0');
        proto_aliases.push(alias);
    }

    proto_aliases.push(vec![b'\0']);
    PROTO_ENTRY = protoent { 
        p_name: proto_name.as_slice().as_ptr() as *const c_char,
        p_aliases: proto_aliases.iter().map(|x| x.as_ptr() as *const i8).collect::<Vec<*const i8>>().as_ptr(),
        p_proto: PROTO_NUM.unwrap()           
    };
        PROTO_ALIASES = Some(proto_aliases);
        PROTO_NAME = Some(proto_name); 
        if PROTO_STAYOPEN == 0 { endprotoent(); }
        &PROTO_ENTRY as *const protoent
}

pub unsafe extern "C" fn getservbyname(
    name: *const c_char,
    proto: *const c_char) 
-> *const servent {

    let mut p: *const servent;

    while { p = getservent(); p!=ptr::null() } {
        if strcmp((*p).s_name, name) == 0 && strcmp((*p).s_proto, proto) == 0 {
            return p;
        }
        loop {
            let mut cp = (*p).s_aliases;
            if cp == ptr::null() {
                break;
            }
            if strcmp(*cp, name) == 0 && strcmp((*p).s_proto, proto) == 0 {
                return p;
            }
            cp = cp.offset(1);
        }
    }
    platform::errno = ENOENT;
    ptr::null() as *const servent
}

pub unsafe extern "C" fn getservbyport(
    port: c_int,
    proto: *const c_char) 
-> *const servent {
    let mut p: *const servent;
    while { p=getservent(); p!=ptr::null()} {
        if (*p).s_port == port && strcmp((*p).s_proto, proto) == 0 {
            return p;
        }
    }
    platform::errno = ENOENT;
    ptr::null()
}

pub unsafe extern "C" fn getservent() -> *const servent {
    if SERVDB == 0 {
        SERVDB = platform::open(b"/etc/services".as_ptr() as *const c_char, O_RDONLY, 0);
        S_LINE = RawLineBuffer::new(SERVDB);
    }

    let mut r: Box<str> = Box::default();
    while r.is_empty() || r.split_whitespace().next() == None || r.starts_with("#") {
        r = match S_LINE.next() {
            Some(s) => s,
            None => {
                if SERV_STAYOPEN == 0 { endservent(); }
                return ptr::null();
            }
        };
    }
    let mut iter: SplitWhitespace = r.split_whitespace();
    let mut serv_name: Vec<u8> = iter.next().unwrap().as_bytes().to_vec();
    serv_name.push(b'\0');
    let port_proto = iter.next().unwrap();
    let mut split = port_proto.split("/");
    let port = atoi(split.next().unwrap().as_ptr() as *const c_char);
    SERV_PORT = Some(port);
    let proto = split.next().unwrap().as_bytes().to_vec();
    
    let mut serv_aliases: Vec<Vec<u8>> = Vec::new();
    loop {
        let mut alias = match iter.next() {
            Some(s) => s.as_bytes().to_vec(),
            None => break
        };
        alias.push(b'\0');
        serv_aliases.push(alias);
    }
    serv_aliases.push(vec![b'\0']);

    SERV_ENTRY = servent {
        s_name: serv_name.as_slice().as_ptr() as *const c_char,
        s_aliases: serv_aliases.iter().map(|x| x.as_ptr() as *const i8).collect::<Vec<*const c_char>>().as_ptr(),
        s_port: SERV_PORT.unwrap(),
        s_proto: proto.as_slice().as_ptr() as *const c_char
    };

    SERV_ALIASES = Some(serv_aliases);
    SERV_NAME = Some(serv_name);
    SERV_PROTO = Some(proto);
    if SERV_STAYOPEN == 0 { endservent(); }

    &SERV_ENTRY as *const servent
}

pub unsafe extern "C" fn sethostent(stayopen: c_int) {
    //TODO stayopen
    if HOSTDB == 0 {
        HOSTDB = platform::open(b"/etc/hosts\0".as_ptr() as *const c_char, O_RDONLY, 0)
    } else {
       platform::lseek(HOSTDB, 0, SEEK_SET);
    }
    H_LINE = RawLineBuffer::new(HOSTDB);
}

pub unsafe extern "C" fn setnetent(stayopen: c_int) {
    NET_STAYOPEN = stayopen;
    if NETDB == 0 {
        NETDB = platform::open(b"/etc/networks\0".as_ptr() as *const c_char, O_RDONLY, 0)
    } else {
       platform::lseek(NETDB, 0, SEEK_SET);
    }
    N_LINE = RawLineBuffer::new(NETDB);
}

pub unsafe extern "C" fn setprotoent(stayopen: c_int) {
    PROTO_STAYOPEN = stayopen;
    if PROTODB == 0 {
        PROTODB = platform::open(b"/etc/protocols\0".as_ptr() as *const c_char, O_RDONLY, 0)
    } else {
       platform::lseek(PROTODB, 0, SEEK_SET);
    }
    P_LINE = RawLineBuffer::new(PROTODB);
}


pub unsafe extern "C" fn setservent(stayopen: c_int) {
    SERV_STAYOPEN = stayopen;
    if SERVDB == 0 {
        SERVDB = platform::open(b"/etc/services\0".as_ptr() as *const c_char, O_RDONLY, 0)
    } else {
       platform::lseek(SERVDB, 0, SEEK_SET);
    }
    S_LINE = RawLineBuffer::new(SERVDB);
}

pub unsafe extern "C" fn getaddrinfo(
    node: *const c_char, 
    service: *const c_char, 
    hints: *const addrinfo,
    res: *mut *mut addrinfo)
-> c_int {
    unimplemented!();
}

pub unsafe extern "C" fn getnameinfo(
    addr: *const sockaddr,
    addrlen: socklen_t,
    host: *mut c_char,
    hostlen: socklen_t,
    serv: *mut c_char,
    servlen: socklen_t,
    flags: c_int) 
-> c_int {
    unimplemented!();
}

pub extern "C" fn freeaddrinfo(res: *mut addrinfo) {
    unimplemented!();
}

pub extern "C" fn gai_strerror(errcode: c_int) -> *const c_char {
    unimplemented!();
}
