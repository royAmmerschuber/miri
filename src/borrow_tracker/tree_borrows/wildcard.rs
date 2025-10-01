use std::cmp::max;

use super::foreign_access_skipping::IdempotentForeignAccess;
use super::perms::Permission;
use super::tree::{AccessRelatedness, Node};
use super::unimap::{UniIndex, UniValMap};
use super::{LocationState, Tree};
use crate::borrow_tracker::GlobalState;
use crate::borrow_tracker::tree_borrows::wildcard;
use crate::{AccessKind, BorTag};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WildcardAccessTracking {
    /// if this tag is directly exposed and with what permissions its exposed
    child_writes: u16,
    child_reads: u16,
    max_foreign_access: IdempotentForeignAccess,
}
impl WildcardAccessTracking {
    pub fn max_child_access(&self, exposed_as: IdempotentForeignAccess) -> IdempotentForeignAccess {
        use IdempotentForeignAccess::*;
        max(
            exposed_as,
            if self.child_writes > 0 {
                Write
            } else if self.child_reads > 0 {
                Read
            } else {
                None
            },
        )
    }
    pub fn access_relatedness(
        &self,
        kind: AccessKind,
        exposed_as: IdempotentForeignAccess,
    ) -> Option<AccessRelatedness> {
        match kind {
            AccessKind::Read => self.read_access_relatedness(exposed_as),
            AccessKind::Write => self.write_access_relatedness(exposed_as),
        }
    }
    pub fn read_access_relatedness(
        &self,
        exposed_as: IdempotentForeignAccess,
    ) -> Option<AccessRelatedness> {
        let has_foreign = self.max_foreign_access >= IdempotentForeignAccess::Read;
        let has_child = self.child_reads > 0 || exposed_as >= IdempotentForeignAccess::Read;
        use AccessRelatedness::*;
        match (has_foreign, has_child) {
            (true, true) => Some(WildcardEitherAccess),
            (true, false) => Some(WildcardForeignAccess),
            (false, true) => Some(WildcardChildAccess),
            (false, false) => None,
        }
    }
    pub fn write_access_relatedness(
        &self,
        exposed_as: IdempotentForeignAccess,
    ) -> Option<AccessRelatedness> {
        let has_foreign = self.max_foreign_access == IdempotentForeignAccess::Write;
        let has_child = self.child_writes > 0 || exposed_as == IdempotentForeignAccess::Write;
        use AccessRelatedness::*;
        match (has_foreign, has_child) {
            (true, true) => Some(WildcardEitherAccess),
            (true, false) => Some(WildcardForeignAccess),
            (false, true) => Some(WildcardChildAccess),
            (false, false) => None,
        }
    }
    pub fn exposed_as(&self, node: &Node, perm: Option<Permission>) -> IdempotentForeignAccess {
        if node.is_exposed {
            let perm = perm.unwrap_or_else(|| node.default_location_state().permission());
            perm.strongest_allowed_child_access()
        } else {
            IdempotentForeignAccess::None
        }
    }
    pub fn get_new_child(&self, exposed_as: IdempotentForeignAccess) -> Self {
        Self {
            max_foreign_access: max(self.max_foreign_access, self.max_child_access(exposed_as)),
            child_reads: 0,
            child_writes: 0,
        }
    }
    /// propagates the wilcard access information over the tree
    /// the `access_type` property is the maximum access type that can happen through this exposed reference
    pub fn update_exposure(
        id: UniIndex,
        old_access_type: IdempotentForeignAccess,
        access_type: IdempotentForeignAccess,
        nodes: &UniValMap<Node>,
        perms: &UniValMap<LocationState>,
        wildcard_accesses: &mut UniValMap<WildcardAccessTracking>,
    ) {
        fn push_relevant_children(
            stack: &mut Vec<UniIndex>,
            is_upgrade: bool,
            access_type: IdempotentForeignAccess,
            access_a: WildcardAccessTracking,
            access_b: WildcardAccessTracking,
            mut children: impl Iterator<Item = UniIndex>,
            nodes: &UniValMap<Node>,
            perms: &UniValMap<LocationState>,
            wildcard_accesses: &mut UniValMap<WildcardAccessTracking>,
        ) {
            use IdempotentForeignAccess::*;
            // how many child accesses we have
            let child_accesses = if is_upgrade {
                if access_type == Write {
                    //upgrading to writes effects writes
                    access_a.child_writes
                } else {
                    //access_type==Read
                    //upgrading from None effects reads and writes
                    access_a.child_reads
                }
            } else {
                if access_type == Read {
                    //downgrading from writes to reads only effects writes
                    access_b.child_writes
                } else {
                    //access_type==None
                    //downgrading to None effects reads and writes
                    access_b.child_reads
                }
            };
            if child_accesses == 0 {
                // no children have child_accesses at this access level, so the parent node
                // has complete influence over the childrens foreign accesses
                // this means every child needs to be updated on a change
                stack.extend(children);
            } else if child_accesses == 1 {
                // there is exactly one child at this access level, so for most children our access change
                // doesnt effect them. except for the child with access rights at at least this level, whose
                // foreign_access is defined by its parent
                stack.push(
                    children
                        .find(|id| {
                            let access = wildcard_accesses.get(*id).unwrap();
                            let node = nodes.get(*id).unwrap();
                            let exposed_as =
                                access.exposed_as(node, perms.get(*id).map(|p| p.permission()));
                            access.max_child_access(exposed_as) >= access_type
                        })
                        .unwrap(),
                );
            } else {
                // there are multiple children with this access level. they are already foreign to each other so
                // the parents access level doesnt effect them. we dont need to update any other children
            }
        }
        let mut entry = wildcard_accesses.entry(id);
        let src_access = entry.or_insert(Default::default());

        // if the exposure doesnt change, then we dont need to update anything
        if old_access_type == access_type {
            return;
        }

        // wether we are upgrading or downgrading the allowed access rights
        let is_upgrade = old_access_type < access_type;

        // stack to process references for which the max_foreign_access field needs to be updated
        let mut stack: Vec<UniIndex> = Vec::new();
        //push own children onto update stack
        if src_access.max_foreign_access < max(access_type, old_access_type) {
            let node = nodes.get(id).unwrap();
            push_relevant_children(
                &mut stack,
                is_upgrade,
                access_type,
                src_access.clone(),
                src_access.clone(),
                node.children.iter().copied(),
                nodes,
                perms,
                wildcard_accesses,
            );
        }

        // we need to propagate the tracking info up the tree, for this we traverse up the parents
        // we can skip propagating info to parents & their other children, if their access permissions
        // dont change (for parents child_permissions and for the other children foreign permissions)
        {
            // we need to keep track of how the previous permissions changed
            let mut prev_old_access = old_access_type;
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
                let exposed_as = access.exposed_as(node, perms.get(id).map(|p| p.permission()));
                let old_max_child_access = old_access.max_child_access(exposed_as);
                let new_max_child_access = access.max_child_access(exposed_as);
                // pushing children who need updating to the stack
                //
                // if this node already has foreign accesses or is itself exposed with stronger access,
                // then we dont need to update its children as they are already exposed to stronger foreign accesses
                if max(exposed_as, old_access.max_foreign_access)
                    < max(access_type, old_access_type)
                {
                    push_relevant_children(
                        &mut stack,
                        is_upgrade,
                        access_type,
                        old_access.clone(),
                        access.clone(),
                        node.children.iter().copied().filter(|id| prev != *id),
                        nodes,
                        perms,
                        wildcard_accesses,
                    );
                }
                if old_max_child_access == new_max_child_access {
                    // child_access didnt change, so we dont need to propagate further upwards
                    break;
                }
                prev_old_access = old_max_child_access;
                prev = id;
            }
        }

        while let Some(id) = stack.pop() {
            let node = nodes.get(id).unwrap();
            let mut entry = wildcard_accesses.entry(id);
            let access = entry.or_insert(Default::default());
            // all items on the stack need this updated
            access.max_foreign_access = access_type;
            let exposed_as = access.exposed_as(node, perms.get(id).map(|p| p.permission()));

            // if this node is already exposed with stronger permissions, then our foreign access wont affect
            // this nodes children
            if exposed_as < max(access_type, old_access_type) {
                push_relevant_children(
                    &mut stack,
                    is_upgrade,
                    access_type,
                    access.clone(),
                    access.clone(),
                    node.children.iter().copied(),
                    nodes,
                    perms,
                    wildcard_accesses,
                );
            }
        }
    }
    pub fn verify_consistency(
        _root: UniIndex,
        _nodes: &UniValMap<Node>,
        _perms: &UniValMap<LocationState>,
        _wildcard_accesses: &mut UniValMap<WildcardAccessTracking>,
    ) {
        todo!();
    }
}
impl Tree {
    pub fn expose_tag(&mut self, tag: BorTag) {
        let id = self.tag_mapping.get(&tag).unwrap();
        let node = self.nodes.get_mut(id).unwrap();
        node.is_exposed = true;
        let node = self.nodes.get(id).unwrap();
        // TODO: only initialize neccessary ranges
        for (_, (perms, wildcard_accesses)) in self.rperms.iter_mut_all() {
            let perm = *perms.entry(id).or_insert(node.default_location_state());

            let access_type = perm.permission().strongest_allowed_child_access();
            WildcardAccessTracking::update_exposure(
                id,
                IdempotentForeignAccess::None,
                access_type,
                &self.nodes,
                perms,
                wildcard_accesses,
            );
        }
    }
}
