//! NT Job Object launcher. Complexity: O(A) arguments and O(1) kernel handles.
use std::ffi::c_void;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;

#[repr(C)]
/// Native basic job limits; O(1) layout.
struct Basic {
    process_time: i64,
    job_time: i64,
    flags: u32,
    minimum: usize,
    maximum: usize,
    active: u32,
    affinity: usize,
    priority: u32,
    scheduling: u32,
}
#[repr(C)]
/// Native extended resource limits; O(1) layout.
struct Extended {
    basic: Basic,
    io: [u64; 6],
    process_memory: usize,
    job_memory: usize,
    peak_process: usize,
    peak_job: usize,
}
#[link(name = "kernel32")]
extern "system" {
    fn CreateJobObjectW(attributes: *const c_void, name: *const u16) -> *mut c_void;
    fn SetInformationJobObject(job: *mut c_void, class: i32, data: *const c_void, len: u32) -> i32;
    fn AssignProcessToJobObject(job: *mut c_void, process: *mut c_void) -> i32;
    fn TerminateJobObject(job: *mut c_void, code: u32) -> i32;
    fn CloseHandle(handle: *mut c_void) -> i32;
}
#[link(name = "ntdll")]
extern "system" {
    fn NtResumeProcess(process: *mut c_void) -> i32;
}

/// Run suspended, assign to the job, then resume; O(A) time and O(1) handles.
pub fn launch(args: &[String], memory: u64) -> io::Result<()> {
    let job = unsafe { CreateJobObjectW(core::ptr::null(), core::ptr::null()) };
    if job.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut limits: Extended = unsafe { core::mem::zeroed() };
    limits.basic.flags = 0x8 | 0x100 | 0x400 | 0x2000;
    limits.basic.active = 1;
    limits.process_memory = memory as usize;
    let result = (|| -> io::Result<()> {
        if unsafe {
            SetInformationJobObject(
                job,
                9,
                &limits as *const _ as *const c_void,
                core::mem::size_of::<Extended>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut child = std::process::Command::new(&args[0])
            .args(&args[1..])
            .creation_flags(4 | 0x08000000)
            .spawn()?;
        if unsafe { AssignProcessToJobObject(job, child.as_raw_handle()) } == 0 {
            let error = io::Error::last_os_error();
            child.kill()?;
            child.wait()?;
            return Err(error);
        }
        if unsafe { NtResumeProcess(child.as_raw_handle()) } < 0 {
            child.kill()?;
            child.wait()?;
            return Err(io::Error::other("NT resume failed"));
        }
        let status = child.wait()?;
        println!(
            "VK_SANDBOX_RESULT={}",
            serde_json::json!({"kernel":"nt-job","target_exit":status.code(),"assigned_before_resume":true})
        );
        if !status.success() {
            return Err(io::Error::other("restricted target returned nonzero"));
        }
        Ok(())
    })();
    unsafe {
        TerminateJobObject(job, 125);
        CloseHandle(job);
    }
    result
}
