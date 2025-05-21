use actix::{dev::MessageResponse, *};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[serde(transparent)]
pub struct InternalId(u64);

impl InternalId {
    pub fn new(id: u64) -> InternalId {
        InternalId(id)
    }
}

impl fmt::Display for InternalId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

// Updated MessageResponse implementation for Actix 0.13
impl<A, M> MessageResponse<A, M> for InternalId
where
    A: Actor,
    M: Message<Result = InternalId>,
{
    fn handle(
        self,
        _: &mut <A as Actor>::Context,
        tx: Option<dev::OneshotSender<<M as Message>::Result>>,
    ) {
        if let Some(tx) = tx {
            tx.send(self).expect("Error when sending InternalId");
        }
    }
}
