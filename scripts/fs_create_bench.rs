use std::ffi::CString;
use std::time::Instant;
extern "C" { fn open(p:*const i8, f:i32, ...)->i32; fn openat(d:i32,p:*const i8,f:i32,...)->i32; fn close(fd:i32)->i32; fn mkdir(p:*const i8,m:u32)->i32; fn mkdirat(d:i32,p:*const i8,m:u32)->i32; }
const O_WRONLY:i32=1; const O_CREAT:i32=0x200; const O_TRUNC:i32=0x400; const O_EXCL:i32=0x800; const O_DIRECTORY:i32=0x100000; const O_RDONLY:i32=0;
fn c(s:&str)->CString{CString::new(s).unwrap()}
fn main(){
    let a:Vec<String>=std::env::args().collect();
    let root=&a[1]; let mode=&a[2]; let nthreads:usize=a[3].parse().unwrap();
    let ndirs=2000usize; let nfiles=60usize; let depth="a/b/c/d/e/f/g";
    let _=std::fs::remove_dir_all(root);
    std::fs::create_dir_all(root).unwrap();
    // layout: root/t{thread}/{depth}/d{i}/f{j}
    for t in 0..nthreads { for i in 0..ndirs/nthreads { std::fs::create_dir_all(format!("{root}/t{t}/{depth}/d{i}")).unwrap(); } }
    let t0=Instant::now();
    let hs:Vec<_>=(0..nthreads).map(|t|{ let root=root.clone(); let mode=mode.clone(); let depth=depth.to_string(); std::thread::spawn(move||{
        for i in 0..ndirs/nthreads { unsafe {
            let dir=format!("{root}/t{t}/{depth}/d{i}");
            match mode.as_str() {
                "path_trunc"|"path_excl" => { let fl=O_WRONLY|O_CREAT|if mode=="path_trunc"{O_TRUNC}else{O_EXCL};
                    for j in 0..nfiles { let p=c(&format!("{dir}/f{j}")); let fd=open(p.as_ptr(),fl,0o666); assert!(fd>=0); close(fd);} }
                _ => { let dp=c(&dir); let dfd=open(dp.as_ptr(),O_RDONLY|O_DIRECTORY); assert!(dfd>=0);
                    let fl=O_WRONLY|O_CREAT|if mode=="at_trunc"{O_TRUNC}else{O_EXCL};
                    for j in 0..nfiles { let p=c(&format!("f{j}")); let fd=openat(dfd,p.as_ptr(),fl,0o666); assert!(fd>=0); close(fd);} close(dfd); }
            } } } }) }).collect();
    for h in hs { h.join().unwrap(); }
    let e=t0.elapsed().as_secs_f64(); let n=ndirs*nfiles;
    println!("{mode:10} thr={nthreads}: {n} files in {e:.2}s = {:.0} us/file/thread, {:.0} files/s", e*1e6*nthreads as f64/n as f64, n as f64/e);
}
