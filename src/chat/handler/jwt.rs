use crate::error::*;
use log::*;

use super::{ChatServer, ClientPacket};
use crate::auth::UserInfo;
use crate::chat::{InternalId, SuccessReason, User, UserSession};
use crate::message::RateLimiter;
use std::collections::HashSet;

impl ChatServer {
    pub(super) fn handle_request_jwt(&mut self, user_id: InternalId) {
        let session = self
            .connections
            .get(&user_id)
            .expect("could not find connection");
        if let Some(auth) = &self.authenticator {
            if let Some(user) = &session.user {
                let token = match auth.new_token(UserInfo {
                    name: user.name.clone(),
                    uuid: user.uuid,
                }) {
                    Ok(token) => token,
                    Err(err) => {
                        warn!("Could not create new token for user `{}`: {}", user_id, err);
                        session.addr.do_send(ClientPacket::Error {
                            message: ClientError::Internal,
                        });
                        return;
                    }
                };
                session.addr.do_send(ClientPacket::NewJWT { token });
            } else {
                info!("User `{}` tried to get JWT but is not logged in.", user_id);
                session.addr.do_send(ClientPacket::Error {
                    message: ClientError::NotLoggedIn,
                });
            }
        } else {
            info!("User `{}` tried to request not supported JWT", user_id);
            session.addr.do_send(ClientPacket::Error {
                message: ClientError::NotSupported,
            });
        }
    }

    pub(super) fn handle_login_jwt(
        &mut self,
        user_id: InternalId,
        jwt: &str,
        allow_messages: bool,
    ) {
        let session = self
            .connections
            .get_mut(&user_id)
            .expect("could not find connection");
        if let Some(auth) = &self.authenticator {
            match auth.auth(jwt) {
                Ok(info) => {
                    self.users
                        .entry(info.name.clone())
                        .or_insert(UserSession {
                            rate_limiter: RateLimiter::new(self.config.message.clone()),
                            connections: HashSet::new(),
                        })
                        .connections
                        .insert(user_id);

                    session.user = Some(User {
                        name: info.name,
                        uuid: info.uuid,
                        allow_messages,
                    });

                    session.addr.do_send(ClientPacket::Success {
                        reason: SuccessReason::Login,
                    });
                }
                Err(err) => {
                    info!("Login of user `{}` using JWT failed: {}", user_id, err);
                    session.addr.do_send(ClientPacket::Error {
                        message: ClientError::LoginFailed,
                    });
                }
            };
        } else {
            info!("User `{}` tried to request not supported JWT", user_id);
            session.addr.do_send(ClientPacket::Error {
                message: ClientError::NotSupported,
            });
        }
    }
}
