// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use crate::error::Error;
use crate::metadata_storage::MetadataStorageInterface;
use futures::{
    channel::{mpsc, oneshot},
    stream::FusedStream,
    SinkExt, Stream,
};
use std::{
    pin::Pin,
    task::{Context, Poll},
};

/// Notifications that can be sent to the state sync driver
pub enum DriverNotification {
    NotifyOnceBootstrapped(oneshot::Sender<Result<(), Error>>), // Notifies the client when the node has bootstrapped
    NotifyOnceRecovered(oneshot::Sender<Result<(), Error>>), // Notifies the client when state sync has recovered after a crash
}

/// A client for sending notifications to the state sync driver
pub struct DriverClient<MetadataStorage> {
    metadata_storage: MetadataStorage,
    notification_sender: mpsc::UnboundedSender<DriverNotification>,
}

impl<MetadataStorage: MetadataStorageInterface + Clone> DriverClient<MetadataStorage> {
    pub fn new(
        metadata_storage: MetadataStorage,
        notification_sender: mpsc::UnboundedSender<DriverNotification>,
    ) -> Self {
        Self {
            metadata_storage,
            notification_sender,
        }
    }

    /// Notifies the caller once state sync has completed
    pub async fn notify_once_completed(&self) -> Result<(), Error> {
        let mut notification_sender = self.notification_sender.clone();
        let (callback_sender, callback_receiver) = oneshot::channel();

        // Create the driver notification depending on the current state
        let driver_notification = if self.metadata_storage.pending_sync_request()?.is_some() {
            DriverNotification::NotifyOnceRecovered(callback_sender)
        } else {
            DriverNotification::NotifyOnceBootstrapped(callback_sender)
        };

        // Send the notification and wait for a response
        notification_sender.send(driver_notification).await?;
        callback_receiver.await?
    }
}

/// A simple listener for client notifications
pub struct ClientNotificationListener {
    // The listener for notifications from clients
    client_notifications: mpsc::UnboundedReceiver<DriverNotification>,
}

impl ClientNotificationListener {
    pub fn new(client_notifications: mpsc::UnboundedReceiver<DriverNotification>) -> Self {
        Self {
            client_notifications,
        }
    }
}

impl Stream for ClientNotificationListener {
    type Item = DriverNotification;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().client_notifications).poll_next(cx)
    }
}

impl FusedStream for ClientNotificationListener {
    fn is_terminated(&self) -> bool {
        self.client_notifications.is_terminated()
    }
}
