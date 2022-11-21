//! Cursor implementation over multiple slices
use std::io::{Seek, SeekFrom};

pub(crate) struct SeqCursor<'s> {
    cursors: Vec<std::io::Cursor<&'s [u8]>>,
    position: u64,
    len: usize,
}

impl<'s> SeqCursor<'s> {
    /// Add an additional slice to the end of the cursor
    ///
    /// Does not modify the current cursors position.
    #[allow(unused)]
    pub(crate) fn add<'b>(&mut self, another: &'b [u8])
    where
        'b: 's,
    {
        let cursor = std::io::Cursor::<&'s [u8]>::new(another);
        self.cursors.push(cursor);
        self.len += another.len();
    }

    /// Crate a new cursor based on a slice of bytes slices.
    pub(crate) fn new<'b>(slices: &[&'b [u8]]) -> Self
    where
        'b: 's,
    {
        let len = slices.iter().fold(0usize, |acc, slice| slice.len() + acc);
        Self {
            cursors: slices
                .iter()
                .map(|slice| std::io::Cursor::new(*slice))
                .collect::<Vec<_>>(),
            position: 0u64,
            len,
        }
    }

    /// Total length of all slices summed up.
    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

impl<'s> std::io::Read for SeqCursor<'s> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut total_read = 0usize;
        let mut acc_offset = 0usize;
        for cursor in self.cursors.iter_mut() {
            let chunk_len = cursor.get_ref().len();
            acc_offset += chunk_len;
            if self.position <= acc_offset as u64 {
                // remaining unread bytes
                let rem_unread_in_chunk = (acc_offset as u64 - self.position) as usize;
                // seek to the beginning of the currently first unread byte in the
                // iterations cursor
                cursor.seek(SeekFrom::Start(
                    chunk_len as u64 - rem_unread_in_chunk as u64,
                ))?;
                let fin = std::cmp::min(total_read + rem_unread_in_chunk, buf.len());
                let read = cursor.read(&mut buf[total_read..fin])?;
                self.position += read as u64;
                total_read += read;
                if total_read >= buf.len() {
                    debug_assert_eq!(total_read, buf.len(), "Always equal. qed");
                    break;
                }
            }
        }
        Ok(total_read)
    }
}

impl<'s> std::io::Seek for SeqCursor<'s> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.position = match pos {
            std::io::SeekFrom::Start(rel) => rel,
            std::io::SeekFrom::End(rel) => {
                let total = self
                    .cursors
                    .iter()
                    .fold(0u64, |acc, cursor| acc + cursor.get_ref().len() as u64);
                (total as i64 + rel) as u64
            }
            std::io::SeekFrom::Current(rel) => (self.position as i64 + rel) as u64,
        };
        Ok(self.position)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Read;
    use std::io::Seek;

    #[test]
    fn sequential_cursor() {
        let c1 = vec![1u8; 17];
        let c2 = vec![2u8; 17];
        let c3 = vec![3u8; 17];

        let mut buf = Vec::<u8>::with_capacity(17 * 3);
        unsafe {
            buf.set_len(17 * 3);
        }
        let mut sq = SeqCursor::new(&[c1.as_slice(), c2.as_slice(), c3.as_slice()]);

        sq.seek(std::io::SeekFrom::Current(16)).unwrap();
        sq.read(&mut buf[0..4]).unwrap();
        assert_eq!(buf[0..4].to_vec(), vec![1u8, 2u8, 2u8, 2u8]);

        sq.seek(std::io::SeekFrom::Current(12)).unwrap();
        sq.read(&mut buf[4..8]).unwrap();
        assert_eq!(buf[4..8].to_vec(), vec![2u8, 2u8, 3u8, 3u8]);
    }

    #[test]
    fn sequential_cursor_with_short_buffer() {
        let c1 = vec![1u8, 2u8];
        let c2 = vec![3u8, 4u8];
        let mut sq = SeqCursor::new(&[c1.as_slice(), c2.as_slice()]);

        //read with a short buffer
        let mut buf = vec![0u8; 1];
        sq.read(&mut buf).unwrap();
        assert_eq!(buf.to_vec(), vec![1u8]);
        sq.read(&mut buf).unwrap();
        assert_eq!(buf.to_vec(), vec![2u8]);
        sq.read(&mut buf).unwrap();
        assert_eq!(buf.to_vec(), vec![3u8]);
        sq.read(&mut buf).unwrap();
        assert_eq!(buf.to_vec(), vec![4u8]);
    }

    #[test]
    fn sequential_cursor_with_seek() {
        let c1 = vec![1u8; 2];
        let c2 = vec![2u8; 2];
        let c3 = vec![3u8; 2];

        let mut buf = vec![0u8; 6];
        // without seek
        let mut sq = SeqCursor::new(&[c1.as_slice(), c2.as_slice(), c3.as_slice()]);
        sq.read(&mut buf).unwrap();
        assert_eq!(buf.to_vec(), vec![1u8, 1u8, 2u8, 2u8, 3u8, 3u8]);

        // seek with start
        let mut buf = vec![0u8; 5];
        sq.seek(SeekFrom::Start(1)).unwrap();
        sq.read(&mut buf).unwrap();
        assert_eq!(buf.to_vec(), vec![1u8, 2u8, 2u8, 3u8, 3u8]);

        //seek with current
        let mut buf = vec![0u8; 5];
        sq.seek(SeekFrom::Start(0)).unwrap();
        sq.seek(SeekFrom::Current(1)).unwrap();
        sq.read(&mut buf).unwrap();
        assert_eq!(buf.to_vec(), vec![1u8, 2u8, 2u8, 3u8, 3u8]);

        //seek with end
        let mut buf = vec![0u8; 3];
        sq.seek(SeekFrom::End(-3)).unwrap();
        sq.read(&mut buf).unwrap();
        assert_eq!(buf.to_vec(), vec![2u8, 3u8, 3u8]);
    }
}
