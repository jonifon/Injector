use std::io::{self, Write};
use std::mem::transmute;
use std::ptr;
use winapi::shared::minwindef::LPVOID;
use winapi::um::memoryapi::{WriteProcessMemory, VirtualAllocEx};
use winapi::um::processthreadsapi::{CreateRemoteThread};
use winapi::um::processthreadsapi::{OpenProcess};
use winapi::um::winnt::{PROCESS_ALL_ACCESS, MEM_COMMIT, PAGE_READWRITE};

use crate::dll_data::get_byte_array;

mod dll_data;

fn main() {
    let mut pid = String::new();
    print!("Введите PID процесса: ");
    io::stdout().flush().unwrap(); 
    io::stdin().read_line(&mut pid).unwrap();
    
    let pid1 : u32 = pid.trim().parse().unwrap();
    
    let bytearray: &[u8] = get_byte_array();
    
    inject(bytearray, &pid1);
    
    
    let mut exit = String::new();
    print!("Нажмите Enter для выхода...");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut exit).unwrap();
}

fn inject(bytearray: &[u8], pid: &u32) {
    unsafe {
        let mut lp_number_of_bytes_written: usize = 0;
        let mut lp_thread_id = 0;
        
        let process_handler = OpenProcess(PROCESS_ALL_ACCESS, 0, *pid);
        if process_handler.is_null() {
           panic!("~> ProcessHandler null!");
       }
        println!("[DEBUG] > Хэндл процесса: {:?}", process_handler);
        
       let alloc_memory = VirtualAllocEx(
           process_handler,
           ptr::null_mut(),
           bytearray.len(),
           MEM_COMMIT,
           PAGE_READWRITE,
       );
       if alloc_memory.is_null(){
           panic!("~> VirtualAllocEx null!");
       }
        println!("[DEBUG] > Выделенная память для процесса: {:?}", alloc_memory);
       
       let write_process_memory_result = WriteProcessMemory(
           process_handler,
           alloc_memory,
           bytearray.as_ptr() as *const winapi::ctypes::c_void,
           bytearray.len(),
           &mut lp_number_of_bytes_written,
       );
       if write_process_memory_result == 0{
           panic!("~> WriteProcessMemoryResult null!");
       } else {
           println!("[DEBUG] > Байты вроде как заинжекчены, открываю поток...");

           let create_remote_thread_result = CreateRemoteThread(
               process_handler,
               ptr::null_mut(),
               0,
               Some(transmute(alloc_memory)), 
               ptr::null_mut(),
               0,
               &mut lp_thread_id,
           );
           if create_remote_thread_result.is_null() {
               panic!("~> CreateRemoteThread null!");
           }
           println!("[DEBUG] > Поток открыт!");
       }

    }
}