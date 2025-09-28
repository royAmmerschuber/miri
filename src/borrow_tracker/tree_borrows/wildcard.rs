use std::cmp::max;

use super::foreign_access_skipping::IdempotentForeignAccess;
use super::tree::{AccessRelatedness, Node};
use super::unimap::{UniIndex, UniValMap};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WildcardAccessTracking {
    /// if this tag is directly exposed and with what permissions its exposed
    is_exposed: IdempotentForeignAccess,
    child_writes: u16,
    child_reads: u16,
    max_foreign_access: IdempotentForeignAccess,
}
impl WildcardAccessTracking {
    pub fn max_child_access(&self) -> IdempotentForeignAccess {
        use IdempotentForeignAccess::*;
        if self.child_writes > 0 || self.is_exposed == Write {
            Write
        } else if self.child_reads > 0 || self.is_exposed == Read {
            Read
        } else {
            None
        }
    }
    pub fn read_access_relatedness(&self) -> Option<AccessRelatedness> {
        let has_foreign = self.max_foreign_access >= IdempotentForeignAccess::Read;
        let has_child = self.child_reads > 0 || self.is_exposed >= IdempotentForeignAccess::Read;
        use AccessRelatedness::*;
        match (has_foreign, has_child) {
            (true, true) => Some(WildcardEitherAccess),
            (true, false) => Some(WildcardForeignAccess),
            (false, true) => Some(WildcardChildAccess),
            (false, false) => None,
        }
    }
    pub fn write_access_relatedness(&self) -> Option<AccessRelatedness> {
        let has_foreign = self.max_foreign_access == IdempotentForeignAccess::Write;
        let has_child = self.child_writes > 0 || self.is_exposed == IdempotentForeignAccess::Write;
        use AccessRelatedness::*;
        match (has_foreign, has_child) {
            (true, true) => Some(WildcardEitherAccess),
            (true, false) => Some(WildcardForeignAccess),
            (false, true) => Some(WildcardChildAccess),
            (false, false) => None,
        }
    }
    /// propagates the wilcard access information over the tree
    /// the `access_type` property is the maximum access type that can happen through this exposed reference
    pub fn propagate_access(
        id: UniIndex,
        access_type: IdempotentForeignAccess,
        nodes: &UniValMap<Node>,
        wildcard_accesses: &mut UniValMap<WildcardAccessTracking>,
    ) {
        let mut entry = wildcard_accesses.entry(id);
        let src_access = entry.or_insert(Default::default());
        let old_access = src_access.is_exposed;

        // if the exposure doesnt change, then we dont need to update anything
        if old_access == access_type {
            return;
        }

        // wether we are upgrading or downgrading the allowed access rights
        let is_upgrade = old_access < access_type;


        src_access.is_exposed = access_type;

        // stack to process references for which the max_foreign_access field needs to be updated
        let mut stack: Vec<UniIndex> = Vec::new();
        //push own children onto update stack
        if src_access.max_foreign_access < access_type{
            use IdempotentForeignAccess::*;
            let node = nodes.get(id).unwrap();
            // how many child accesses we have
            let child_accesses = if is_upgrade {
                if access_type == Write {
                    //upgrading to writes effects writes
                    src_access.child_writes
                } else {
                    //access_type==Read
                    //upgrading from None effects reads and writes
                    src_access.child_reads
                }
            } else {
                if access_type == Read {
                    //downgrading from writes to reads only effects writes
                    src_access.child_writes
                } else {
                    //access_type==None
                    //downgrading to None effects reads and writes
                    src_access.child_reads
                }
            };
            if child_accesses == 0 {
                // no children have child_accesses at this access level, so the parent node
                // has complete influence over the childrens foreign accesses
                // this means every child needs to be updated on a change
                stack.extend(node.children.iter().copied());
            } else if child_accesses == 1 {
                // there is exactly one child at this access level, so for most children our access change
                // doesnt effect them. except for the child with access rights at at least this level, whose
                // foreign_access is defined by its parent
                stack.push(
                    node.children
                        .iter()
                        .copied()
                        .find(|id| {
                            let access = wildcard_accesses.get(*id).unwrap();
                            access.max_child_access() >= access_type
                        })
                        .unwrap(),
                );
            } else {
                // there are multiple children with this access level. they are already foreign to each other so
                // the parents access level doesnt effect them. we dont need to update any other children
            }
        }

        // we need to propagate the tracking info up the tree, for this we traverse up the parents
        // we can skip propagating info to parents & their other children, if their access permissions
        // dont change (for parents child_permissions and for the other children foreign permissions)
        {
            // we need to keep track of how the previous permissions changed
            let mut prev_old_access = old_access;
            let mut prev = id;
            while let Some(id) = nodes.get(prev).unwrap().parent {
                let node = nodes.get(id).unwrap();
                let mut entry = wildcard_accesses.entry(id);
                let access = entry.or_insert(Default::default());

                let old_access = access.clone();
                use IdempotentForeignAccess::*;
                // updating this nodes tracking data for children
                if is_upgrade {
                    if access_type == Write {
                        access.child_writes += 1;
                    }
                    if prev_old_access == None {
                        access.child_reads += 1;
                    }
                } else {
                    if prev_old_access == Write {
                        access.child_writes -= 1;
                    }
                    if access_type == None {
                        access.child_reads -= 1;
                    }
                }
                // pushing children who need updating to the stack
                //
                // if this node already has foreign accesses or is itself exposed with stronger access,
                // then we dont need to update its children as they are already exposed to stronger foreign accesses
                if max(old_access.is_exposed, old_access.max_foreign_access) < access_type {
                    // how many child accesses we have not counting the previous node
                    let child_accesses = if is_upgrade {
                        if access_type == Write {
                            //upgrading to writes effects writes
                            old_access.child_writes
                        } else {
                            //access_type==Read
                            //upgrading from None effects reads and writes
                            old_access.child_reads
                        }
                    } else {
                        if access_type == Read {
                            //downgrading from writes to reads only effects writes
                            access.child_writes
                        } else {
                            //access_type==None
                            //downgrading to None effects reads and writes
                            access.child_reads
                        }
                    };
                    if child_accesses == 0 {
                        // no other children have child_accesses at this access level, so the previous node
                        // has complete influence over the other nodes foreign accesses
                        // this means every child (except prev) needs to be updated on a change
                        stack.reserve(node.children.len() - 1);
                        stack.extend(node.children.iter().copied().filter(|id| prev != *id));
                    } else if child_accesses == 1 {
                        // there is exactly one other node at this access level, so for most children our access change
                        // doesnt effect them. except for the other node with access rights at this level, whose
                        // foreign_access is defined by prev
                        stack.push(
                            node.children
                                .iter()
                                .copied()
                                .find(|id| {
                                    let access = wildcard_accesses.get(*id).unwrap();
                                    *id != prev && access.max_child_access() >= access_type
                                })
                                .unwrap(),
                        );
                    } else {
                        // there are multiple other children with this access level. they are already foreign to each other so
                        // prev access level doesnt effect them. we dont need to update any other children
                    }
                }

                if old_access.max_child_access() == access_type {
                    // child_access didnt change, so we dont need to propagate further upwards
                    break;
                }
                prev_old_access = old_access.max_child_access();
                prev = id;
            }
        }

        while let Some(id) = stack.pop() {
            let node = nodes.get(id).unwrap();
            let mut entry = wildcard_accesses.entry(id);
            let access = entry.or_insert(Default::default());
            // all items on the stack need this updated
            access.max_foreign_access = access_type;

            use IdempotentForeignAccess::*;
            // if this node is already exposed with stronger permissions, then our foreign access wont affect
            // this nodes children
            if access.is_exposed < access_type {
                // how many child accesses we have
                let child_accesses = if is_upgrade {
                    if access_type == Write {
                        //upgrading to writes effects writes
                        access.child_writes
                    } else {
                        //access_type==Read
                        //upgrading from None effects reads and writes
                        access.child_reads
                    }
                } else {
                    if access_type == Read {
                        //downgrading from writes to reads only effects writes
                        access.child_writes
                    } else {
                        //access_type==None
                        //downgrading to None effects reads and writes
                        access.child_reads
                    }
                };
                if child_accesses == 0 {
                    // no children have child_accesses at this access level, so the parent node
                    // has complete influence over the childrens foreign accesses
                    // this means every child needs to be updated on a change
                    stack.extend(node.children.iter().copied());
                } else if child_accesses == 1 {
                    // there is exactly one child at this access level, so for most children our access change
                    // doesnt effect them. except for the child with access rights at at least this level, whose
                    // foreign_access is defined by its parent
                    stack.push(
                        node.children
                            .iter()
                            .copied()
                            .find(|id| {
                                let access = wildcard_accesses.get(*id).unwrap();
                                access.max_child_access() >= access_type
                            })
                            .unwrap(),
                    );
                } else {
                    // there are multiple children with this access level. they are already foreign to each other so
                    // the parents access level doesnt effect them. we dont need to update any other children
                }
            }
        }
    }
}
