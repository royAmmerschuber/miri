//@compile-flags: -Zmiri-tree-borrows -Zmiri-permissive-provenance

#[allow(unused_variables)]
pub fn main() {
    let mut x: u32 = 42;

    let ptr_base = &mut x as *mut u32;
    let ref1 = unsafe { &mut *ptr_base };
    let ref2 = unsafe { &mut *ptr_base };

    let int2 = ref2 as *mut u32 as usize;

    let wild = int1 as *mut u32;
    fn protect(ref3: &mut u32) {
        let int3 = ref3 as *mut u32 as usize;
        //    ┌────────────┐
        //    │            │
        //    │  ptr_base  ├──────────────┐
        //    │            │              │
        //    └──────┬─────┘              │
        //           │                    │
        //           │                    │
        //           ▼                    ▼
        //    ┌────────────┐       ┌────────────┐
        //    │            │       │            │
        //    │ ref1(Res)  │       │ ref2(Res)* │
        //    │            │       │            │
        //    └──────┬─────┘       └────────────┘
        //           │
        //           │
        //           ▼
        //    ┌────────────┐
        //    │            │
        //    │ ref3(Res)* │
        //    │            │
        //    └────────────┘

        // since ref3 is protected, we know that every write from outside it will be UB
        // this means we know that the access is through ref3
        let wild = int3 as *mut u32;
        unsafe { wild.write(13) }
    }
    protect(ref1);

    // ref 2 is disabled
    let fail = *ref2;
}
