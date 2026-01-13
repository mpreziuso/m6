//! Error type for the FAT32 filesystem service.

#![allow(dead_code)]

use crate::block::BlockError;
use crate::ipc::response;

/// Filesystem error type
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FsError {
    /// Generic I/O error
    Io,
    /// File or directory not found
    NotFound,
    /// File or directory already exists
    AlreadyExists,
    /// Expected directory but found file
    NotDirectory,
    /// Expected file but found directory
    IsDirectory,
    /// Directory not empty
    NotEmpty,
    /// No space left on device
    NoSpace,
    /// Invalid filename
    InvalidName,
    /// Invalid handle
    InvalidHandle,
    /// Too many open files
    TooManyOpen,
    /// Filesystem not mounted
    NotMounted,
    /// Read-only filesystem
    ReadOnly,
    /// End of file/directory
    EndOfFile,
    /// Invalid argument
    InvalidArg,
    /// Filesystem corrupted
    Corrupted,
    /// Unsupported operation
    Unsupported,
}

impl FsError {
    /// Convert to IPC response code
    pub fn to_response(self) -> u64 {
        match self {
            Self::Io => response::ERR_IO,
            Self::NotFound => response::ERR_NOT_FOUND,
            Self::AlreadyExists => response::ERR_EXISTS,
            Self::NotDirectory => response::ERR_NOT_DIR,
            Self::IsDirectory => response::ERR_IS_DIR,
            Self::NotEmpty => response::ERR_NOT_EMPTY,
            Self::NoSpace => response::ERR_NO_SPACE,
            Self::InvalidName => response::ERR_NAME_TOO_LONG,
            Self::InvalidHandle => response::ERR_HANDLE_INVALID,
            Self::TooManyOpen => response::ERR_TOO_MANY_OPEN,
            Self::NotMounted => response::ERR_NOT_MOUNTED,
            Self::ReadOnly => response::ERR_READ_ONLY,
            Self::EndOfFile => response::ERR_END_OF_DIR,
            Self::InvalidArg => response::ERR_INVALID,
            Self::Corrupted => response::ERR_IO,
            Self::Unsupported => response::ERR_INVALID,
        }
    }

    /// Convert from embedded-sdmmc error
    pub fn from_sdmmc<E: core::fmt::Debug>(err: embedded_sdmmc::Error<E>) -> Self {
        match err {
            embedded_sdmmc::Error::DeviceError(_) => Self::Io,
            embedded_sdmmc::Error::FormatError(_) => Self::Corrupted,
            embedded_sdmmc::Error::NoSuchVolume => Self::NotMounted,
            embedded_sdmmc::Error::FilenameError(_) => Self::InvalidName,
            embedded_sdmmc::Error::TooManyOpenVolumes => Self::TooManyOpen,
            embedded_sdmmc::Error::TooManyOpenDirs => Self::TooManyOpen,
            embedded_sdmmc::Error::TooManyOpenFiles => Self::TooManyOpen,
            embedded_sdmmc::Error::BadHandle => Self::InvalidHandle,
            embedded_sdmmc::Error::NotFound => Self::NotFound,
            embedded_sdmmc::Error::FileAlreadyOpen => Self::TooManyOpen,
            embedded_sdmmc::Error::DirAlreadyOpen => Self::TooManyOpen,
            embedded_sdmmc::Error::OpenedDirAsFile => Self::IsDirectory,
            embedded_sdmmc::Error::OpenedFileAsDir => Self::NotDirectory,
            embedded_sdmmc::Error::DeleteDirAsFile => Self::IsDirectory,
            embedded_sdmmc::Error::VolumeStillInUse => Self::TooManyOpen,
            embedded_sdmmc::Error::VolumeAlreadyOpen => Self::TooManyOpen,
            embedded_sdmmc::Error::Unsupported => Self::Unsupported,
            embedded_sdmmc::Error::EndOfFile => Self::EndOfFile,
            embedded_sdmmc::Error::BadCluster => Self::Corrupted,
            embedded_sdmmc::Error::ConversionError => Self::InvalidArg,
            embedded_sdmmc::Error::NotEnoughSpace => Self::NoSpace,
            embedded_sdmmc::Error::AllocationError => Self::NoSpace,
            embedded_sdmmc::Error::UnterminatedFatChain => Self::Corrupted,
            embedded_sdmmc::Error::ReadOnly => Self::ReadOnly,
            embedded_sdmmc::Error::FileAlreadyExists => Self::AlreadyExists,
            embedded_sdmmc::Error::BadBlockSize(_) => Self::Corrupted,
            embedded_sdmmc::Error::InvalidOffset => Self::InvalidArg,
            embedded_sdmmc::Error::DiskFull => Self::NoSpace,
            embedded_sdmmc::Error::DirAlreadyExists => Self::AlreadyExists,
        }
    }

    /// Convert from block error
    pub fn from_block(err: BlockError) -> Self {
        match err {
            BlockError::IpcError => Self::Io,
            BlockError::IoError => Self::Io,
            BlockError::NotReady => Self::NotMounted,
        }
    }
}
