// Copyright 2025 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::ops::{Deref, DerefMut};

/// An `Augmented` value is a generic wrapper that holds a primary value of type `T` and an
/// optional auxiliary value of type `A`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Augmented<T, A: Clone> {
    /// The primary value, without any auxiliary data.
    Primary(T),
    /// The primary value, with auxiliary data.
    WithAux(T, A),
}

impl<T, A: Clone> Augmented<T, A> {
    /// Maps an `Augmented<T, A>` to an `Augmented<U, A>` by applying a function to the contained
    /// primary value, leaving the auxiliary value untouched.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Augmented<U, A> {
        match self {
            Self::Primary(t) => Augmented::Primary(f(t)),
            Self::WithAux(t, aux) => Augmented::WithAux(f(t), aux),
        }
    }

    /// Extracts the primary value, discarding the auxiliary value if it exists.
    pub fn extract(self) -> T {
        match self {
            Self::Primary(t) => t,
            Self::WithAux(t, _) => t,
        }
    }

    /// Converts an `Augmented<T, A>` to an `Augmented<&T, A>`.
    pub fn as_ref(&self) -> Augmented<&T, A> {
        match self {
            Self::Primary(t) => Augmented::Primary(t),
            Self::WithAux(t, aux) => Augmented::WithAux(t, aux.clone()),
        }
    }

    /// Converts an `Augmented<T, A>` to an `Augmented<&mut T, A>`.
    pub fn as_mut(&mut self) -> Augmented<&mut T, A> {
        match self {
            Self::Primary(t) => Augmented::Primary(t),
            Self::WithAux(t, aux) => Augmented::WithAux(t, aux.clone()),
        }
    }
}

impl<T, A: Clone> Augmented<&mut T, A> {
    /// Converts an `Augmented<&mut T, A>` to an `Augmented<&T, A>`.
    pub fn as_unmut(&self) -> Augmented<&T, A> {
        match self {
            Self::Primary(t) => Augmented::Primary(t),
            Self::WithAux(t, aux) => Augmented::WithAux(t, aux.clone()),
        }
    }
}

impl<T, A: Clone> Augmented<Option<T>, A> {
    /// Transposes an `Augmented<Option<T>, A>` into an `Option<Augmented<T, A>>`.
    pub fn transpose(self) -> Option<Augmented<T, A>> {
        match self {
            Self::Primary(t) => Some(Augmented::Primary(t?)),
            Self::WithAux(t, aux) => Some(Augmented::WithAux(t?, aux)),
        }
    }
}

impl<T, A: Clone, E> Augmented<Result<T, E>, A> {
    /// Transposes an `Augmented<Result<T, E>, A>` into a `Result<Augmented<T, A>, E>`.
    pub fn transpose(self) -> Result<Augmented<T, A>, E> {
        match self {
            Self::Primary(t) => Ok(Augmented::Primary(t?)),
            Self::WithAux(t, aux) => Ok(Augmented::WithAux(t?, aux)),
        }
    }
}

impl<T, A: Clone> From<T> for Augmented<T, A> {
    /// Creates a `Primary` `Augmented` value from a primary value.
    fn from(t: T) -> Self {
        Self::Primary(t)
    }
}

impl<T, A: Clone> Deref for Augmented<T, A> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Primary(t) => t,
            Self::WithAux(t, _) => t,
        }
    }
}

impl<T, A: Clone> DerefMut for Augmented<T, A> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Primary(t) => t,
            Self::WithAux(t, _) => t,
        }
    }
}
