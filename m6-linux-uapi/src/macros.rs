// Forked from Fuchsia's linux_uapi, adapted for no_std.
// Original: Copyright 2025 The Fuchsia Authors. BSD license.

/// Get the size of a field in a struct.
#[macro_export]
macro_rules! size_of_field {
    ($type_name:ty, $($field:ident).+) => {{
        const fn size_of_pointee<T>(_val: *const T) -> usize {
            core::mem::size_of::<T>()
        }
        const fn compute() -> usize {
            let p = core::mem::MaybeUninit::<$type_name>::uninit();
            // SAFETY: pointer is never dereferenced; used only in const context
            // to compute the type of the field.
            size_of_pointee(unsafe { &raw const (*p.as_ptr()) . $($field).+ })
        }
        const size: usize = compute();
        size
    }};
}

/// Ensure two types have the same layout.
#[macro_export]
macro_rules! check_same_layout {
    {} => {};
    {
        $type_name1:ty = $type_name2:ty
        {
            $(
                $($field1:ident).+ => $($field2:ident).+
            ),*
            $(,)?
        }
        $($token:tt)*
    } => {
        $crate::__static_assertions::assert_eq_size!($type_name1, $type_name2);
        $(
            $crate::__static_assertions::const_assert_eq!(
                core::mem::offset_of!($type_name1, $($field1).+),
                core::mem::offset_of!($type_name2, $($field2).+)
            );
        )*
        $crate::check_same_layout! { $($token)* }
    };
}

/// Ensure a UAPI type has the same layout in 32 and 64 bits.
#[macro_export]
macro_rules! check_arch_independent_layout {
    {} => {};
    {
        $type_name:ident {
            $( $($field:ident).+ ),*
            $(,)?
        }
        $($token:tt)*
    }=> {
        $crate::check_same_layout! {
            $crate::$type_name = $crate::arch32::$type_name {
                $(
                    $($field).+ => $($field).+,
                )*
            }
        }
        $crate::check_arch_independent_layout! { $($token)* }
    };
}

/// Ensure a custom type has the same layout as an ABI-independent UAPI type.
#[macro_export]
macro_rules! check_arch_independent_same_layout {
    {} => {};
    {
        $type_name1:ty = $type_name2:ident
        {
            $(
                $($field1:ident).+ => $($field2:ident).+
            ),*
            $(,)?
        }
        $($token:tt)*
    } => {
        $crate::check_same_layout! {
            $type_name1 = $crate::$type_name2
            {
                $($($field1).+ => $($field2).+,)*
            }
        }
        $crate::check_same_layout! {
            $type_name1 = $crate::arch32::$type_name2
            {
                $($($field1).+ => $($field2).+,)*
            }
        }
        $crate::check_arch_independent_same_layout! { $($token)* }
    };
}

/// Implement From/TryFrom between two structs.
#[macro_export]
macro_rules! translate_data {
    {} => {};
    {
        $(#[$meta:meta])*
        BidiFrom<$type_name1:ty, $type_name2:ty> {
            $(
                $field1:ident = $field2:ident;
            )*
            $(..$($d1:expr)?, $($d2:expr)?)?
        }
        $($token:tt)*
    } => {
        $crate::translate_data! {
            $(#[$meta])*
            From<$type_name1> for $type_name2 {
                $( $field2 = $field1; )*
                $($(..$d2)?)?
            }
            $(#[$meta])*
            From<$type_name2> for $type_name1 {
                $( $field1 = $field2; )*
                $($(..$d1)?)?
            }
        }
        $crate::translate_data! { $($token)* }
    };
    {
        $(#[$meta:meta])*
        BidiTryFrom<$type_name1:ty, $type_name2:ty> {
            $(
                $field1:ident = $field2:ident;
            )*
            $(..$($d1:expr)?, $($d2:expr)?)?
        }
        $($token:tt)*
    } => {
        $crate::translate_data! {
            $(#[$meta])*
            TryFrom<$type_name1> for $type_name2 {
                $( $field2 = $field1; )*
                $($(..$d2)?)?
            }
            $(#[$meta])*
            TryFrom<$type_name2> for $type_name1 {
                $( $field1 = $field2; )*
                $($(..$d1)?)?
            }
        }
        $crate::translate_data! { $($token)* }
    };
    {
        $(#[$meta:meta])*
        From<$type_name1:ty> for $type_name2:ty {
            $(
                $field2:ident = $field1:ident;
            )*
            $(..$d:expr)?
        }
        $($token:tt)*
    } => {
        $(#[$meta])*
        impl From<$type_name1> for $type_name2 {
            fn from(src: $type_name1) -> Self {
                Self {
                    $( $field2: src.$field1.into(), )*
                    $(..$d)?
                }
            }
        }
        $crate::translate_data! { $($token)* }
    };
    {
        $(#[$meta:meta])*
        TryFrom<$type_name1:ty> for $type_name2:ty {
            $(
                $field2:ident = $field1:ident $( ( $field1_default:expr ))?;
            )*
            $(..$d:expr)?
        }
        $($token:tt)*
    } => {
        $(#[$meta])*
        impl TryFrom<$type_name1> for $type_name2 {
            type Error = ();
            fn try_from(src: $type_name1) -> Result<Self, ()> {
                Ok(Self {
                    $( $field2: $crate::translate_data_expr!( src.$field1 $( ( $field1_default ) )? ), )*
                    $(..$d)?
                })
            }
        }
        $crate::translate_data! { $($token)* }
    };
}

#[macro_export]
macro_rules! translate_data_expr {
    ( $src:ident . $field:ident ) => {
        $src.$field.try_into().map_err(|_| ())?
    };
    ( $src:ident . $field:ident ( $field1_default:expr ) ) => {
        $src.$field.try_into().unwrap_or($field1_default)
    };
}

/// Implement From/TryFrom between two UAPI structs of different ABI.
#[macro_export]
macro_rules! arch_translate_data {
    {} => {};
    {
        BidiFrom<$type_name:ident> {
            $( $field:ident ),+
            $(,)?
        }
        $($token:tt)*
    } => {
        $crate::arch_translate_data! {
            TryFrom64<$type_name> {
                $(
                    $field,
                )*
            }
            From32<$type_name> {
                $(
                    $field,
                )*
            }
        }
        $crate::arch_translate_data! { $($token)* }
    };
    {
        TryFrom64<$type_name:ident> {
            $( $field:ident ),+
            $(,)?
        }
        $($token:tt)*
    } => {
        $crate::translate_data! {
            TryFrom<$crate::$type_name> for $crate::arch32::$type_name {
                $(
                    $field = $field;
                )*
                ..Default::default()
            }
        }
        $crate::arch_translate_data! { $($token)* }
    };
    {
        From32<$type_name:ident> {
            $( $field:ident ),+
            $(,)?
        }
        $($token:tt)*
    } => {
        $crate::translate_data! {
            From<$crate::arch32::$type_name> for $crate::$type_name {
                $(
                    $field = $field;
                )*
                ..Default::default()
            }
        }
        $crate::arch_translate_data! { $($token)* }
    };
}

/// Implement TryFrom between two UAPI structs of different ABI with a common type.
#[macro_export]
macro_rules! arch_map_data {
    {} => {};
    {
        BidiTryFrom<$type_name1:ty, $type_name2:ident> {
            $(
                $field1:ident = $field2:ident;
            )*
            $(..$d:expr)?
        }
        $($token:tt)*
    } => {
        $crate::translate_data! {
            BidiTryFrom<$type_name1, $crate::$type_name2> {
                $(
                    $field1 = $field2;
                )*
                ..$($d)?, Default::default()
            }
            BidiTryFrom<$type_name1, $crate::arch32::$type_name2> {
                $(
                    $field1 = $field2;
                )*
                ..$($d)?, Default::default()
            }
        }
        $crate::arch_map_data! { $($token)* }
    };
}
