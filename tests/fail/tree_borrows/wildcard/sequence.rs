//@compile-flags: -Zmiri-tree-borrows

pub fn main() {
    let mut x: u32 = 42;

    let ref1 = &mut x;
    let int1 = ref1 as *mut u32 as usize;

    let ref2 = &mut *ref1;

    let ref3 = &mut *ref2;
    let int3 = ref3 as *mut u32 as usize;

    let wild = int1 as *mut u32;

    // graph TD
    // ref1(Res)* --> ref2(Res) --> ref3(Res)*
    //
    //     ┌────────────┐
    //     │            │
    //     │ ref1(Res)* │
    //     │            │
    //     └──────┬─────┘
    //            │
    //            │
    //            ▼
    //     ┌────────────┐
    //     │            │
    //     │ ref2(Res)  │
    //     │            │
    //     └──────┬─────┘
    //            │
    //            │
    //            ▼
    //     ┌────────────┐
    //     │            │
    //     │ ref3(Res)* │
    //     │            │
    //     └────────────┘

    // writes through either ref1 or ref3, which is either a child or foreign access to ref2.
    unsafe { wild.write(42) };

    //reading from ref2 still works since the previous access could have been through its child
    //this also freezes ref3
    let x = *ref2;

    // we can still write through wild, as there is still the exposed ref1 with write permissions
    // disables ref2,ref3
    unsafe { wild.write(43) };

    // fails because ref2 is disables
    let fail = *ref2;
}
