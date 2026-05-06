package smb

import "testing"

func TestRemotePathExcludedMatchesBareDirectorySegment(t *testing.T) {
	t.Parallel()

	cases := []string{
		"fakturabehandling/XML/invoice.xml",
		"uq/local/fakturabehandling/XML/invoice.xml",
		`uq\local\fakturabehandling\XML\invoice.xml`,
	}

	for _, path := range cases {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			if !remotePathExcluded(path, "fakturabehandling") {
				t.Fatalf("expected %q to be excluded by bare segment", path)
			}
		})
	}
}

func TestRemotePathExcludedKeepsExplicitPathAsPrefixOnly(t *testing.T) {
	t.Parallel()

	if !remotePathExcluded("uq/local/fakturabehandling/XML/invoice.xml", "uq/local") {
		t.Fatal("expected explicit path prefix to exclude nested path")
	}
	if remotePathExcluded("archive/uq/local/invoice.xml", "uq/local") {
		t.Fatal("did not expect explicit path pattern to match in the middle of a path")
	}
}

func TestRemotePathExcludedIsCaseInsensitiveForBareSegment(t *testing.T) {
	t.Parallel()

	if !remotePathExcluded("uq/local/FakturaBehandling/XML/invoice.xml", "fakturabehandling") {
		t.Fatal("expected bare segment exclusion to be case insensitive")
	}
}

func TestRemotePathExcludedTrimsSlashesAroundBareSegment(t *testing.T) {
	t.Parallel()

	if !remotePathExcluded(`\uq\local\XML\Inng\2\ok\file.txt`, `\xml\`) {
		t.Fatal("expected slash-wrapped bare segment to exclude matching path segment")
	}
}

func TestRemotePathExcludedDoesNotTreatSlashWrappedSegmentAsExtension(t *testing.T) {
	t.Parallel()

	if remotePathExcluded(`\uq\local\Inng\2\ok\file.xml`, `\xml\`) {
		t.Fatal("did not expect slash-wrapped segment to match file extension")
	}
}
