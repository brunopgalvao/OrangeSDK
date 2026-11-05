//! Instance memory: regions, faults, and heap growth (spec 01 §3).

use alloc::vec;
use alloc::vec::Vec;

/// Size of a page in bytes.
pub const PAGE: u32 = 4096;
/// Lowest address a region may start at (spec 01 §3.2, null guard).
pub const NULL_GUARD_END: u32 = 0x1_0000;
/// Highest address a region may end at (spec 01 §3.2, top guard).
pub const TOP_GUARD_START: u32 = 0xFFFF_0000;
/// Maximum `ro_size + data_size + bss_size` (spec 01 §9).
pub const MAX_STATIC_BYTES: u64 = 1 << 30;
/// Maximum `heap_max + stack size` (spec 01 §9).
pub const MAX_DYNAMIC_BYTES: u64 = 1 << 31;

/// The nine layout values of a module's memory section (spec 03 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryLayout {
    /// Start of read-only data.
    pub ro_base: u32,
    /// Bytes of read-only data.
    pub ro_size: u32,
    /// Start of read-write data.
    pub rw_base: u32,
    /// Bytes of initialised read-write data.
    pub data_size: u32,
    /// Bytes of zero-initialised data following `data`.
    pub bss_size: u32,
    /// Start of the heap.
    pub heap_base: u32,
    /// Maximum heap size.
    pub heap_max: u32,
    /// Lowest stack address.
    pub stack_base: u32,
    /// One past the highest stack address; initial `sp`.
    pub stack_top: u32,
}

/// A layout rule violation (spec 03 §7.2, rules 5, 6, 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    /// A base or limit that must be page-aligned is not (rule 5).
    Misaligned,
    /// Regions are out of order, overlap, or lack a guard page, or a base is
    /// inside a guard (rule 6).
    Order,
    /// A size limit of spec 01 §9 is exceeded (rule 8).
    Limits,
}

const fn round_up_page(v: u64) -> u64 {
    v.div_ceil(PAGE as u64) * PAGE as u64
}

impl MemoryLayout {
    /// Size of the read-write region: `data_size + bss_size`.
    #[must_use]
    pub const fn rw_size(&self) -> u64 {
        self.data_size as u64 + self.bss_size as u64
    }

    /// Checks rules 5, 6, and 8 of spec 03 §7.2.
    ///
    /// # Errors
    /// The first violated rule.
    pub fn validate(&self) -> Result<(), LayoutError> {
        let aligned = [
            self.ro_base,
            self.rw_base,
            self.heap_base,
            self.heap_max,
            self.stack_base,
            self.stack_top,
        ];
        if aligned.iter().any(|v| v % PAGE != 0) {
            return Err(LayoutError::Misaligned);
        }
        let page = u64::from(PAGE);
        let rodata_end = round_up_page(u64::from(self.ro_base) + u64::from(self.ro_size));
        let data_end = round_up_page(u64::from(self.rw_base) + self.rw_size());
        let heap_end = u64::from(self.heap_base) + u64::from(self.heap_max);
        let ordered = u64::from(self.ro_base) >= u64::from(NULL_GUARD_END)
            && rodata_end + page <= u64::from(self.rw_base)
            && data_end + page <= u64::from(self.heap_base)
            && heap_end + page <= u64::from(self.stack_base)
            && self.stack_base < self.stack_top
            && self.stack_top <= TOP_GUARD_START;
        if !ordered {
            return Err(LayoutError::Order);
        }
        let static_bytes = u64::from(self.ro_size) + self.rw_size();
        let dynamic_bytes = u64::from(self.heap_max) + u64::from(self.stack_top - self.stack_base);
        if static_bytes > MAX_STATIC_BYTES || dynamic_bytes > MAX_DYNAMIC_BYTES {
            return Err(LayoutError::Limits);
        }
        Ok(())
    }
}

/// An access outside the mapped regions or a write to read-only memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryFault;

#[derive(Clone, Copy)]
enum Region {
    Ro,
    Rw,
    Heap,
    Stack,
}

#[derive(Clone, Copy)]
enum Writable {
    Rw,
    Heap,
    Stack,
}

impl From<Writable> for Region {
    fn from(w: Writable) -> Region {
        match w {
            Writable::Rw => Region::Rw,
            Writable::Heap => Region::Heap,
            Writable::Stack => Region::Stack,
        }
    }
}

/// The backing bytes of every mapped region, for execution backends that
/// access instance memory natively (spec 07 §4). Each entry is the region's
/// guest base address and exactly its current extent, so an access of `n`
/// bytes at `a` is inside it when `base <= a` and `a + n <= base + len`.
#[derive(Debug)]
pub struct Regions<'a> {
    /// Read-only data.
    pub ro: (u32, &'a [u8]),
    /// Read-write data: `data` followed by `bss`.
    pub rw: (u32, &'a mut [u8]),
    /// The heap at its current size.
    pub heap: (u32, &'a mut [u8]),
    /// The stack.
    pub stack: (u32, &'a mut [u8]),
}

/// The memory of one instance.
#[derive(Debug, Clone)]
pub struct Memory {
    layout: MemoryLayout,
    ro: Vec<u8>,
    rw: Vec<u8>,
    heap: Vec<u8>,
    stack: Vec<u8>,
}

fn to_usize(v: u64) -> usize {
    usize::try_from(v).expect("validated region sizes fit the address space")
}

impl Memory {
    /// Builds the initial memory image (spec 01 §3.3). The layout must already
    /// be validated and `rodata`, `data` must have the sizes it declares.
    ///
    /// # Panics
    /// If a region size does not fit `usize`, which a validated layout rules out
    /// on every supported target.
    #[must_use]
    pub fn new(layout: MemoryLayout, rodata: &[u8], data: &[u8]) -> Memory {
        debug_assert_eq!(rodata.len(), layout.ro_size as usize);
        debug_assert_eq!(data.len(), layout.data_size as usize);
        let mut rw = Vec::with_capacity(to_usize(layout.rw_size()));
        rw.extend_from_slice(data);
        rw.resize(to_usize(layout.rw_size()), 0);
        Memory {
            layout,
            ro: rodata.to_vec(),
            rw,
            heap: Vec::new(),
            stack: vec![0; (layout.stack_top - layout.stack_base) as usize],
        }
    }

    /// The layout this memory was built from.
    #[must_use]
    pub const fn layout(&self) -> &MemoryLayout {
        &self.layout
    }

    /// Every region with its backing bytes (see [`Regions`]).
    pub fn regions_mut(&mut self) -> Regions<'_> {
        let l = &self.layout;
        Regions {
            ro: (l.ro_base, &self.ro),
            rw: (l.rw_base, &mut self.rw),
            heap: (l.heap_base, &mut self.heap),
            stack: (l.stack_base, &mut self.stack),
        }
    }

    /// Current heap size in bytes, always a multiple of the page size.
    #[must_use]
    pub fn heap_size(&self) -> u32 {
        u32::try_from(self.heap.len()).unwrap_or(u32::MAX)
    }

    /// One past the last heap byte: `heap_base + heap_size`.
    #[must_use]
    pub fn heap_end(&self) -> u32 {
        self.layout.heap_base + self.heap_size()
    }

    /// The number of pages [`Memory::sbrk`] would add for `bytes`, or `None` if
    /// the growth would exceed `heap_max`.
    #[must_use]
    pub fn sbrk_pages(&self, bytes: u32) -> Option<u32> {
        let grow = round_up_page(u64::from(bytes));
        if u64::from(self.heap_size()) + grow > u64::from(self.layout.heap_max) {
            return None;
        }
        #[allow(clippy::cast_possible_truncation)]
        Some((grow / u64::from(PAGE)) as u32)
    }

    /// Grows the heap by `bytes` rounded up to whole pages (spec 02 §4 `sbrk`).
    /// Returns the previous heap end and the number of pages added, or `None`
    /// if the growth would exceed `heap_max`, in which case nothing changes.
    pub fn sbrk(&mut self, bytes: u32) -> Option<(u32, u32)> {
        let pages = self.sbrk_pages(bytes)?;
        let old_end = self.heap_end();
        let new_size = u64::from(self.heap_size()) + u64::from(pages) * u64::from(PAGE);
        self.heap.resize(to_usize(new_size), 0);
        Some((old_end, pages))
    }

    fn locate_writable(&self, addr: u32, len: u32) -> Result<(Writable, usize), MemoryFault> {
        if len == 0 {
            // An empty range touches no byte and is valid anywhere; empty
            // buffers routinely carry dangling pointers.
            return Ok((Writable::Rw, 0));
        }
        let start = u64::from(addr);
        let end = start + u64::from(len);
        let l = &self.layout;
        let within =
            |base: u32, size: u64| start >= u64::from(base) && end <= u64::from(base) + size;
        let (region, base) = if within(l.rw_base, l.rw_size()) {
            (Writable::Rw, l.rw_base)
        } else if within(l.heap_base, self.heap.len() as u64) {
            (Writable::Heap, l.heap_base)
        } else if within(l.stack_base, self.stack.len() as u64) {
            (Writable::Stack, l.stack_base)
        } else {
            return Err(MemoryFault);
        };
        Ok((region, (addr - base) as usize))
    }

    fn locate(&self, addr: u32, len: u32) -> Result<(Region, usize), MemoryFault> {
        if len == 0 {
            return Ok((Region::Rw, 0));
        }
        let start = u64::from(addr);
        let end = start + u64::from(len);
        let l = &self.layout;
        if start >= u64::from(l.ro_base) && end <= u64::from(l.ro_base) + u64::from(l.ro_size) {
            return Ok((Region::Ro, (addr - l.ro_base) as usize));
        }
        self.locate_writable(addr, len)
            .map(|(w, off)| (Region::from(w), off))
    }

    fn slice(&self, region: Region, offset: usize, len: usize) -> &[u8] {
        let v = match region {
            Region::Ro => &self.ro,
            Region::Rw => &self.rw,
            Region::Heap => &self.heap,
            Region::Stack => &self.stack,
        };
        &v[offset..offset + len]
    }

    fn slice_mut(&mut self, region: Writable, offset: usize, len: usize) -> &mut [u8] {
        let v = match region {
            Writable::Rw => &mut self.rw,
            Writable::Heap => &mut self.heap,
            Writable::Stack => &mut self.stack,
        };
        &mut v[offset..offset + len]
    }

    /// Reads `len` bytes at `addr`.
    ///
    /// # Errors
    /// [`MemoryFault`] if any byte is unmapped.
    pub fn read(&self, addr: u32, len: u32) -> Result<&[u8], MemoryFault> {
        let (region, offset) = self.locate(addr, len)?;
        Ok(self.slice(region, offset, len as usize))
    }

    /// Reads a little-endian unsigned value of `width` bytes (1, 2, 4, or 8).
    ///
    /// # Errors
    /// [`MemoryFault`] if any byte is unmapped.
    pub fn read_uint(&self, addr: u32, width: u32) -> Result<u64, MemoryFault> {
        let bytes = self.read(addr, width)?;
        let mut v: u64 = 0;
        for (i, b) in bytes.iter().enumerate() {
            v |= u64::from(*b) << (8 * i);
        }
        Ok(v)
    }

    /// Writes `data` at `addr`.
    ///
    /// # Errors
    /// [`MemoryFault`] if any byte is unmapped or read-only; nothing is written.
    pub fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), MemoryFault> {
        let len = u32::try_from(data.len()).map_err(|_| MemoryFault)?;
        let (region, offset) = self.locate_writable(addr, len)?;
        self.slice_mut(region, offset, data.len())
            .copy_from_slice(data);
        Ok(())
    }

    /// Writes the low `width` bytes of `value`, little-endian.
    ///
    /// # Errors
    /// [`MemoryFault`] if any byte is unmapped or read-only.
    pub fn write_uint(&mut self, addr: u32, width: u32, value: u64) -> Result<(), MemoryFault> {
        let bytes = value.to_le_bytes();
        self.write(addr, &bytes[..width as usize])
    }

    /// `memcopy` (spec 02 §4): copies `len` bytes from `src` to `dst` as if
    /// through a temporary buffer. Both ranges are checked before any write.
    ///
    /// # Errors
    /// [`MemoryFault`] if the source is not readable or the destination not writable.
    pub fn copy(&mut self, dst: u32, src: u32, len: u32) -> Result<(), MemoryFault> {
        let (src_region, src_off) = self.locate(src, len)?;
        let (dst_region, dst_off) = self.locate_writable(dst, len)?;
        let tmp = self.slice(src_region, src_off, len as usize).to_vec();
        self.slice_mut(dst_region, dst_off, len as usize)
            .copy_from_slice(&tmp);
        Ok(())
    }

    /// `memfill` (spec 02 §4): writes `value` to `len` bytes at `dst`.
    ///
    /// # Errors
    /// [`MemoryFault`] if the destination is not writable.
    pub fn fill(&mut self, dst: u32, value: u8, len: u32) -> Result<(), MemoryFault> {
        let (region, offset) = self.locate_writable(dst, len)?;
        self.slice_mut(region, offset, len as usize).fill(value);
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A small valid layout used across the crate's tests.
    pub(crate) const fn small_layout() -> MemoryLayout {
        MemoryLayout {
            ro_base: 0x1_0000,
            ro_size: 16,
            rw_base: 0x2_0000,
            data_size: 8,
            bss_size: 24,
            heap_base: 0x3_0000,
            heap_max: 0x1_0000,
            stack_base: 0xFFFC_0000,
            stack_top: 0xFFFE_0000,
        }
    }

    fn mem() -> Memory {
        let rodata: Vec<u8> = (0u8..16).collect();
        Memory::new(small_layout(), &rodata, &[1, 2, 3, 4, 5, 6, 7, 8])
    }

    #[test]
    fn layout_validation() {
        let l = small_layout();
        assert_eq!(l.validate(), Ok(()));
        assert_eq!(l.rw_size(), 32);

        let mut m = l;
        m.rw_base += 1;
        assert_eq!(m.validate(), Err(LayoutError::Misaligned));

        let mut m = l;
        m.ro_base = 0;
        assert_eq!(m.validate(), Err(LayoutError::Order));
        let mut m = l;
        m.rw_base = 0x1_0000; // no guard page after rodata
        assert_eq!(m.validate(), Err(LayoutError::Order));
        let mut m = l;
        m.heap_base = 0x2_0000;
        assert_eq!(m.validate(), Err(LayoutError::Order));
        let mut m = l;
        m.heap_max = 0xFFFC_0000 - 0x3_0000; // heap end touches stack without a guard
        assert_eq!(m.validate(), Err(LayoutError::Order));
        let mut m = l;
        m.stack_top = m.stack_base;
        assert_eq!(m.validate(), Err(LayoutError::Order));
        let mut m = l;
        m.stack_top = 0xFFFF_1000;
        assert_eq!(m.validate(), Err(LayoutError::Order));

        // Limits: 1 GiB + 1 of static bytes, laid out legally.
        let big = MemoryLayout {
            ro_base: 0x1_0000,
            ro_size: 0x4000_0000,
            rw_base: 0x4002_0000,
            data_size: 1,
            bss_size: 0,
            heap_base: 0x4004_0000,
            heap_max: 0x1000,
            stack_base: 0x4006_0000,
            stack_top: 0x4007_0000,
        };
        assert_eq!(big.validate(), Err(LayoutError::Limits));
        let big_dyn = MemoryLayout {
            ro_base: 0x1_0000,
            ro_size: 0,
            rw_base: 0x2_0000,
            data_size: 0,
            bss_size: 0,
            heap_base: 0x3_0000,
            heap_max: 0x7FFF_0000,
            stack_base: 0x8003_0000,
            stack_top: 0x8004_1000,
        };
        assert_eq!(big_dyn.validate(), Err(LayoutError::Limits));
        let mut exactly = big_dyn;
        exactly.stack_top = 0x8004_0000; // exactly 2 GiB is allowed
        assert_eq!(exactly.validate(), Ok(()));
    }

    #[test]
    fn initial_contents_and_regions() {
        let m = mem();
        assert_eq!(m.layout(), &small_layout());
        assert_eq!(
            m.read(0x1_0000, 16).unwrap(),
            &(0u8..16).collect::<Vec<_>>()[..]
        );
        assert_eq!(m.read(0x2_0000, 8).unwrap(), &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(m.read(0x2_0008, 24).unwrap(), &[0u8; 24]);
        assert_eq!(m.read_uint(0x2_0000, 4).unwrap(), 0x0403_0201);
        assert_eq!(m.read_uint(0x2_0000, 8).unwrap(), 0x0807_0605_0403_0201);
        assert_eq!(m.read_uint(0xFFFC_0000, 1).unwrap(), 0);
        assert_eq!(m.heap_size(), 0);
        assert_eq!(m.heap_end(), 0x3_0000);
    }

    #[test]
    fn faults() {
        let mut m = mem();
        assert_eq!(m.read(0, 1), Err(MemoryFault));
        assert_eq!(m.read(0xFFFF_0000, 1), Err(MemoryFault));
        assert_eq!(m.read(0xFFFF_FFFF, 1), Err(MemoryFault));
        assert_eq!(m.read(0x1_0000, 17), Err(MemoryFault)); // runs past rodata
        assert_eq!(m.read(0x1_000F, 2), Err(MemoryFault)); // crosses into guard
        assert_eq!(m.read(0x3_0000, 1), Err(MemoryFault)); // heap not grown
        assert_eq!(m.write(0x1_0000, &[0]), Err(MemoryFault)); // read-only
        assert_eq!(m.write(0x2_0000, &[0; 33]), Err(MemoryFault)); // past bss
        assert_eq!(m.write(0xFFFD_FFFF, &[0, 0]), Err(MemoryFault)); // crosses stack top
        assert_eq!(m.copy(0x2_0000, 0x3_0000, 1), Err(MemoryFault)); // bad source
        assert_eq!(m.copy(0x1_0000, 0x2_0000, 1), Err(MemoryFault)); // bad destination
        assert_eq!(m.fill(0x1_0000, 1, 1), Err(MemoryFault));
        // Data is untouched after faults.
        assert_eq!(m.read(0x2_0000, 8).unwrap(), &[1, 2, 3, 4, 5, 6, 7, 8]);
        // A zero-length access touches nothing and succeeds anywhere.
        assert_eq!(m.read(0, 0).unwrap(), &[]);
        assert_eq!(m.write(0, &[]), Ok(()));
        assert_eq!(m.copy(0, 0xFFFF_FFFF, 0), Ok(()));
        assert_eq!(m.fill(0, 1, 0), Ok(()));
        assert_eq!(m.read(0x1_0000, 0).unwrap(), &[]);
    }

    #[test]
    fn writes_copies_and_fills() {
        let mut m = mem();
        m.write_uint(0x2_0010, 8, 0x1122_3344_5566_7788).unwrap();
        assert_eq!(m.read_uint(0x2_0010, 8).unwrap(), 0x1122_3344_5566_7788);
        m.write_uint(0x2_0010, 2, 0xFFFF_AAAA).unwrap();
        assert_eq!(m.read_uint(0x2_0010, 4).unwrap(), 0x5566_AAAA);
        // Misaligned and cross-byte accesses are fine inside a region.
        m.write(0xFFFC_0001, &[9, 9, 9]).unwrap();
        assert_eq!(m.read_uint(0xFFFC_0000, 4).unwrap(), 0x0909_0900);
        // Copy rodata into the stack, then overlapping copy within the stack.
        m.copy(0xFFFC_0100, 0x1_0000, 16).unwrap();
        assert_eq!(
            m.read(0xFFFC_0100, 16).unwrap(),
            &(0u8..16).collect::<Vec<_>>()[..]
        );
        m.copy(0xFFFC_0104, 0xFFFC_0100, 8).unwrap();
        assert_eq!(
            m.read(0xFFFC_0100, 12).unwrap(),
            &[0, 1, 2, 3, 0, 1, 2, 3, 4, 5, 6, 7]
        );
        m.fill(0xFFFC_0100, 0xAB, 4).unwrap();
        assert_eq!(
            m.read(0xFFFC_0100, 5).unwrap(),
            &[0xAB, 0xAB, 0xAB, 0xAB, 0]
        );
    }

    #[test]
    fn regions_expose_exact_extents() {
        let mut m = mem();
        m.sbrk(1).unwrap();
        let r = m.regions_mut();
        assert_eq!((r.ro.0, r.ro.1.len()), (0x1_0000, 16));
        assert_eq!((r.rw.0, r.rw.1.len()), (0x2_0000, 32));
        assert_eq!((r.heap.0, r.heap.1.len()), (0x3_0000, 4096));
        assert_eq!((r.stack.0, r.stack.1.len()), (0xFFFC_0000, 0x2_0000));
        r.stack.1[0] = 9;
        r.rw.1[31] = 7;
        assert!(alloc::format!("{r:?}").contains("Regions"));
        assert_eq!(m.read(0xFFFC_0000, 1).unwrap(), &[9]);
        assert_eq!(m.read(0x2_001F, 1).unwrap(), &[7]);
    }

    #[test]
    fn sbrk_grows_in_pages_up_to_heap_max() {
        let mut m = mem();
        assert_eq!(m.sbrk(0), Some((0x3_0000, 0)));
        assert_eq!(m.sbrk(1), Some((0x3_0000, 1)));
        assert_eq!(m.heap_size(), PAGE);
        assert_eq!(m.heap_end(), 0x3_1000);
        m.write(0x3_0FFF, &[7]).unwrap();
        assert_eq!(m.read(0x3_1000, 1), Err(MemoryFault));
        assert_eq!(m.sbrk(PAGE * 2 + 1), Some((0x3_1000, 3)));
        assert_eq!(m.heap_size(), PAGE * 4);
        // 16 pages max; 12 more fit exactly, then nothing.
        assert_eq!(m.sbrk(PAGE * 12), Some((0x3_4000, 12)));
        assert_eq!(m.sbrk(1), None);
        assert_eq!(m.sbrk_pages(1), None);
        assert_eq!(m.sbrk_pages(0), Some(0));
        assert_eq!(m.heap_size(), 0x1_0000);
        assert_eq!(m.read_uint(0x3_0FFF, 1).unwrap(), 7);
        let clone = m.clone();
        assert_eq!(clone.heap_end(), m.heap_end());
        assert!(alloc::format!("{m:?}").contains("Memory"));
        assert_eq!(alloc::format!("{:?}", LayoutError::Limits), "Limits");
    }
}
