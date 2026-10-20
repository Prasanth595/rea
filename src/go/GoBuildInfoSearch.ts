import {
  BinaryFormatFailure,
  BinaryReader,
  mappedFileOffset,
  type BinaryContainer,
  type FileMapping,
} from "../native/metadata/BinaryContainer.js";

/** Go owns build-info section selection and validity; native readers only own container facts. */
export const goBuildInfoSearch = (
  bytes: Buffer,
  container: BinaryContainer,
): readonly FileMapping[] => {
  const reader = new BinaryReader(bytes, container.byte_order === "little");
  const named: FileMapping[] = [];
  for (const section of container.sections) {
    if (section.format === "elf" && section.name === ".go.buildinfo") {
      if (named.length !== 0)
        throw new BinaryFormatFailure(
          "malformed",
          "ELF contains ambiguous build-info sections",
        );
      if (section.type !== 1)
        throw new BinaryFormatFailure(
          "malformed",
          "ELF build-info section is not file-backed data",
        );
      if (section.compressed)
        throw new BinaryFormatFailure(
          "unsupported",
          "Compressed ELF build-info sections are unsupported",
        );
      const search = {
        ...reader.fileRange(
          section.declared_range.offset,
          section.declared_range.size,
          "ELF build-info section",
        ),
        address: section.address,
      };
      if (
        mappedFileOffset(
          container.mappings,
          search.address,
          search.size,
          container.zero_fills,
        ) !== search.offset
      )
        throw new BinaryFormatFailure(
          "malformed",
          "ELF build-info section disagrees with its load mapping",
        );
      named.push(search);
    } else if (
      section.format === "macho" &&
      section.section_name === "__go_buildinfo"
    ) {
      if (section.segment_unmapped)
        throw new BinaryFormatFailure(
          "malformed",
          "Mach-O build-info section is in an unmapped segment",
        );
      if (section.segment_mapping === null)
        throw new BinaryFormatFailure(
          "malformed",
          "Mach-O build-info section is not file mapped",
        );
      if ([1, 0xc, 0x12].includes(section.type))
        throw new BinaryFormatFailure(
          "malformed",
          "Mach-O build-info section is zero-fill data",
        );
      const search = {
        ...reader.fileRange(
          section.declared_range.offset,
          section.declared_range.size,
          "Mach-O build-info section",
        ),
        address: section.address,
      };
      if (
        mappedFileOffset(
          [section.segment_mapping],
          search.address,
          search.size,
        ) !== search.offset
      )
        throw new BinaryFormatFailure(
          "malformed",
          "Mach-O build-info section disagrees with its segment",
        );
      named.push(search);
    }
  }
  if (named.length > 1)
    throw new BinaryFormatFailure(
      "malformed",
      "Mach-O has ambiguous build-info sections",
    );
  return named.length > 0 ? named : container.data_ranges;
};
