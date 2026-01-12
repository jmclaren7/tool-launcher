<?php
// Configuration
$validKey = 'ChangeMe123';
$dataDir = __DIR__ . '/data';
$enableDebug = false; // Set to true to enable debug features (?debug=1)

// Check for key in GET or POST
$key = isset($_GET['key']) ? $_GET['key'] : (isset($_POST['key']) ? $_POST['key'] : null);

if ($key !== $validKey) {
    http_response_code(403);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Invalid or missing key']);
    exit;
}

// Debug mode - add ?debug=1 to check GD status
if ($enableDebug && isset($_GET['debug'])) {
    header('Content-Type: text/plain');
    echo "GD Available: " . (function_exists('imagecreatetruecolor') ? 'Yes' : 'No') . "\n";
    if (function_exists('gd_info')) {
        echo "GD Info:\n";
        print_r(gd_info());
    }
    echo "\nPHP Version: " . phpversion() . "\n";

    // Test icon extraction if a file is specified
    if (isset($_GET['testfile'])) {
        // Sanitize path - allow subfolders but prevent traversal
        $requestedFile = $_GET['testfile'];
        $requestedFile = str_replace('\\', '/', $requestedFile);
        $requestedFile = preg_replace('/\.\.+/', '', $requestedFile);
        $requestedFile = ltrim($requestedFile, '/');

        $testFile = $dataDir . '/' . $requestedFile;
        $realDataDir = realpath($dataDir);
        $realTestFile = realpath($testFile);

        echo "\nTesting icon extraction for: $testFile\n";
        echo "File exists: " . (file_exists($testFile) ? 'Yes' : 'No') . "\n";

        if ($realTestFile && strpos($realTestFile, $realDataDir) === 0 && is_file($realTestFile)) {
            $icon = extractExeIconDebug($realTestFile);
            echo "Icon extracted: " . ($icon ? 'Yes (' . strlen($icon) . ' bytes base64)' : 'No') . "\n";
            if ($icon) {
                echo "\nBase64 icon (first 100 chars): " . substr($icon, 0, 100) . "...\n";
            }
        } else {
            echo "File not accessible or outside data directory\n";
        }
    } else {
        echo "\nTo test a specific exe, add &testfile=folder/filename.exe\n";
    }
    exit;
}

function extractExeIconDebug($filePath) {
    $fp = @fopen($filePath, 'rb');
    if (!$fp) { echo "DEBUG: Cannot open file\n"; return null; }

    // Read DOS header
    $dosHeader = @fread($fp, 64);
    if (!$dosHeader || strlen($dosHeader) < 64) { fclose($fp); echo "DEBUG: Invalid DOS header\n"; return null; }
    if (substr($dosHeader, 0, 2) !== 'MZ') { fclose($fp); echo "DEBUG: Not MZ executable\n"; return null; }

    $peOffsetData = unpack('V', substr($dosHeader, 60, 4));
    if (!$peOffsetData) { fclose($fp); echo "DEBUG: Cannot read PE offset\n"; return null; }
    $peOffset = $peOffsetData[1];
    echo "DEBUG: PE offset = $peOffset\n";

    if ($peOffset <= 0 || $peOffset > 10000000) { fclose($fp); echo "DEBUG: Invalid PE offset\n"; return null; }
    fseek($fp, $peOffset);

    $peSignature = @fread($fp, 4);
    if ($peSignature !== "PE\x00\x00") { fclose($fp); echo "DEBUG: Invalid PE signature\n"; return null; }
    echo "DEBUG: Valid PE signature\n";

    $coffHeader = @fread($fp, 20);
    if (!$coffHeader || strlen($coffHeader) < 20) { fclose($fp); echo "DEBUG: Invalid COFF header\n"; return null; }

    $numSectionsData = unpack('v', substr($coffHeader, 2, 2));
    $optionalHeaderSizeData = unpack('v', substr($coffHeader, 16, 2));
    if (!$numSectionsData || !$optionalHeaderSizeData) { fclose($fp); echo "DEBUG: Cannot read COFF\n"; return null; }

    $numSections = $numSectionsData[1];
    $optionalHeaderSize = $optionalHeaderSizeData[1];
    echo "DEBUG: Sections=$numSections, OptHeaderSize=$optionalHeaderSize\n";

    if ($optionalHeaderSize <= 0 || $optionalHeaderSize > 10000) { fclose($fp); echo "DEBUG: Invalid optional header size\n"; return null; }

    $optionalHeader = @fread($fp, $optionalHeaderSize);
    if (!$optionalHeader || strlen($optionalHeader) < $optionalHeaderSize) { fclose($fp); echo "DEBUG: Cannot read optional header\n"; return null; }

    $magicData = unpack('v', substr($optionalHeader, 0, 2));
    if (!$magicData) { fclose($fp); echo "DEBUG: Cannot read magic\n"; return null; }
    $magic = $magicData[1];
    $is64 = ($magic === 0x20b);
    echo "DEBUG: Magic=0x" . dechex($magic) . " (" . ($is64 ? "PE32+" : "PE32") . ")\n";

    // Data directories start at offset 112 (PE32+) or 96 (PE32)
    // Resource Table is the 3rd entry (index 2), so add 16 bytes (2 * 8)
    $dataDirOffset = $is64 ? (112 + 16) : (96 + 16);
    if (strlen($optionalHeader) < $dataDirOffset + 8) { fclose($fp); echo "DEBUG: Optional header too small for data dirs\n"; return null; }

    $resourceRVAData = unpack('V', substr($optionalHeader, $dataDirOffset, 4));
    if (!$resourceRVAData) { fclose($fp); echo "DEBUG: Cannot read resource RVA\n"; return null; }
    $resourceRVA = $resourceRVAData[1];
    echo "DEBUG: Resource RVA = 0x" . dechex($resourceRVA) . "\n";

    if ($resourceRVA === 0) { fclose($fp); echo "DEBUG: No resource section (RVA=0)\n"; return null; }

    // Read sections
    $sections = [];
    for ($i = 0; $i < $numSections; $i++) {
        $sectionHeader = @fread($fp, 40);
        if (!$sectionHeader || strlen($sectionHeader) < 40) { fclose($fp); echo "DEBUG: Cannot read section $i\n"; return null; }

        $vs = unpack('V', substr($sectionHeader, 8, 4));
        $va = unpack('V', substr($sectionHeader, 12, 4));
        $rs = unpack('V', substr($sectionHeader, 16, 4));
        $rp = unpack('V', substr($sectionHeader, 20, 4));
        if (!$vs || !$va || !$rs || !$rp) continue;

        $name = rtrim(substr($sectionHeader, 0, 8), "\x00");
        $sections[] = [
            'name' => $name,
            'virtualSize' => $vs[1],
            'virtualAddress' => $va[1],
            'rawSize' => $rs[1],
            'rawPointer' => $rp[1],
        ];
        echo "DEBUG: Section '$name' VA=0x" . dechex($va[1]) . " Size=" . $vs[1] . "\n";
    }

    // Find resource section
    $resourceSection = null;
    foreach ($sections as $section) {
        if ($resourceRVA >= $section['virtualAddress'] &&
            $resourceRVA < $section['virtualAddress'] + $section['virtualSize']) {
            $resourceSection = $section;
            break;
        }
    }
    if (!$resourceSection) { fclose($fp); echo "DEBUG: Resource RVA not in any section\n"; return null; }
    echo "DEBUG: Resource section found: " . $resourceSection['name'] . "\n";

    $resourceFileOffset = $resourceSection['rawPointer'] + ($resourceRVA - $resourceSection['virtualAddress']);
    echo "DEBUG: Resource file offset = $resourceFileOffset\n";

    // Read resource directory
    $readResourceDir = function($offset) use ($fp, $resourceFileOffset) {
        if ($offset <= 0) return [];
        if (fseek($fp, $offset) !== 0) return [];
        $dirData = @fread($fp, 16);
        if (!$dirData || strlen($dirData) < 16) return [];
        $numNamedData = unpack('v', substr($dirData, 12, 2));
        $numIdData = unpack('v', substr($dirData, 14, 2));
        if (!$numNamedData || !$numIdData) return [];
        $totalEntries = $numNamedData[1] + $numIdData[1];
        if ($totalEntries <= 0 || $totalEntries > 1000) return [];

        $entries = [];
        for ($i = 0; $i < $totalEntries; $i++) {
            $entryData = @fread($fp, 8);
            if (!$entryData || strlen($entryData) < 8) break;
            $idData = unpack('V', substr($entryData, 0, 4));
            $offsetData = unpack('V', substr($entryData, 4, 4));
            if (!$idData || !$offsetData) continue;
            $id = $idData[1];
            $offsetOrData = $offsetData[1];
            $isDir = ($offsetOrData & 0x80000000) !== 0;
            $entryOffset = $offsetOrData & 0x7FFFFFFF;
            $entries[] = ['id' => $id, 'offset' => $resourceFileOffset + $entryOffset, 'isDir' => $isDir];
        }
        return $entries;
    };

    $rootEntries = $readResourceDir($resourceFileOffset);
    echo "DEBUG: Root entries count = " . count($rootEntries) . "\n";
    if (empty($rootEntries)) { fclose($fp); echo "DEBUG: No root entries\n"; return null; }

    // List resource types
    $groupIconEntry = null;
    $iconEntry = null;
    foreach ($rootEntries as $entry) {
        $typeName = $entry['id'];
        if ($entry['id'] === 3) $typeName = "3 (RT_ICON)";
        if ($entry['id'] === 14) $typeName = "14 (RT_GROUP_ICON)";
        echo "DEBUG: Resource type $typeName\n";
        if ($entry['id'] === 14) $groupIconEntry = $entry;
        if ($entry['id'] === 3) $iconEntry = $entry;
    }

    if (!$groupIconEntry) { fclose($fp); echo "DEBUG: No RT_GROUP_ICON found\n"; return null; }
    if (!$iconEntry) { fclose($fp); echo "DEBUG: No RT_ICON found\n"; return null; }

    fclose($fp);
    echo "DEBUG: Icon resources found, calling normal extraction...\n";

    // Call the normal function to complete extraction
    return extractExeIcon($filePath);
}

// Check if file download is requested
if (isset($_GET['file'])) {
    $requestedFile = $_GET['file'];

    // Prevent directory traversal
    $requestedFile = str_replace('\\', '/', $requestedFile);
    $requestedFile = preg_replace('/\.\.+/', '', $requestedFile);
    $requestedFile = ltrim($requestedFile, '/');

    $filePath = $dataDir . '/' . $requestedFile;
    $realDataDir = realpath($dataDir);
    $realFilePath = realpath($filePath);

    // Verify file exists and is within data directory
    if ($realFilePath === false || strpos($realFilePath, $realDataDir) !== 0 || !is_file($realFilePath)) {
        http_response_code(404);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'File not found']);
        exit;
    }

    // Serve the file
    $filename = basename($realFilePath);
    $filesize = filesize($realFilePath);

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Length: ' . $filesize);

    readfile($realFilePath);
    exit;
}

// Return JSON tool list
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

$result = [];

function extractExeIcon($filePath) {
    // Native PHP PE icon extraction
    $fp = @fopen($filePath, 'rb');
    if (!$fp) return null;

    try {
        // Read DOS header
        $dosHeader = @fread($fp, 64);
        if (!$dosHeader || strlen($dosHeader) < 64) { fclose($fp); return null; }
        if (substr($dosHeader, 0, 2) !== 'MZ') { fclose($fp); return null; }

        // Get PE header offset
        $peOffsetData = unpack('V', substr($dosHeader, 60, 4));
        if (!$peOffsetData) { fclose($fp); return null; }
        $peOffset = $peOffsetData[1];

        if ($peOffset <= 0 || $peOffset > 10000000) { fclose($fp); return null; }
        fseek($fp, $peOffset);

        // Read PE signature
        $peSignature = @fread($fp, 4);
        if ($peSignature !== "PE\x00\x00") { fclose($fp); return null; }

        // Read COFF header
        $coffHeader = @fread($fp, 20);
        if (!$coffHeader || strlen($coffHeader) < 20) { fclose($fp); return null; }

        $numSectionsData = unpack('v', substr($coffHeader, 2, 2));
        $optionalHeaderSizeData = unpack('v', substr($coffHeader, 16, 2));
        if (!$numSectionsData || !$optionalHeaderSizeData) { fclose($fp); return null; }

        $numSections = $numSectionsData[1];
        $optionalHeaderSize = $optionalHeaderSizeData[1];

        if ($optionalHeaderSize <= 0 || $optionalHeaderSize > 10000) { fclose($fp); return null; }

        // Read optional header to get data directories
        $optionalHeader = @fread($fp, $optionalHeaderSize);
        if (!$optionalHeader || strlen($optionalHeader) < $optionalHeaderSize) { fclose($fp); return null; }

        // Determine if PE32 or PE32+
        $magicData = unpack('v', substr($optionalHeader, 0, 2));
        if (!$magicData) { fclose($fp); return null; }
        $magic = $magicData[1];
        $is64 = ($magic === 0x20b);

        // Data directories start at offset 112 (PE32+) or 96 (PE32)
        // Resource Table is the 3rd entry (index 2), so add 16 bytes (2 * 8)
        $dataDirOffset = $is64 ? (112 + 16) : (96 + 16);
        if (strlen($optionalHeader) < $dataDirOffset + 8) { fclose($fp); return null; }

        $resourceRVAData = unpack('V', substr($optionalHeader, $dataDirOffset, 4));
        if (!$resourceRVAData) { fclose($fp); return null; }
        $resourceRVA = $resourceRVAData[1];
        if ($resourceRVA === 0) { fclose($fp); return null; }

        // Read section headers to find resource section
        $sections = [];
        for ($i = 0; $i < $numSections; $i++) {
            $sectionHeader = @fread($fp, 40);
            if (!$sectionHeader || strlen($sectionHeader) < 40) { fclose($fp); return null; }

            $vs = unpack('V', substr($sectionHeader, 8, 4));
            $va = unpack('V', substr($sectionHeader, 12, 4));
            $rs = unpack('V', substr($sectionHeader, 16, 4));
            $rp = unpack('V', substr($sectionHeader, 20, 4));
            if (!$vs || !$va || !$rs || !$rp) continue;

            $sections[] = [
                'name' => rtrim(substr($sectionHeader, 0, 8), "\x00"),
                'virtualSize' => $vs[1],
                'virtualAddress' => $va[1],
                'rawSize' => $rs[1],
                'rawPointer' => $rp[1],
            ];
        }

        // Find section containing resource RVA
        $resourceSection = null;
        foreach ($sections as $section) {
            if ($resourceRVA >= $section['virtualAddress'] &&
                $resourceRVA < $section['virtualAddress'] + $section['virtualSize']) {
                $resourceSection = $section;
                break;
            }
        }
        if (!$resourceSection) { fclose($fp); return null; }

        // Calculate file offset of resource directory
        $resourceFileOffset = $resourceSection['rawPointer'] + ($resourceRVA - $resourceSection['virtualAddress']);

        // Helper function to read resource directory
        $readResourceDir = function($offset) use ($fp, $resourceFileOffset) {
            if ($offset <= 0) return [];
            if (fseek($fp, $offset) !== 0) return [];

            $dirData = @fread($fp, 16);
            if (!$dirData || strlen($dirData) < 16) return [];

            $numNamedData = unpack('v', substr($dirData, 12, 2));
            $numIdData = unpack('v', substr($dirData, 14, 2));
            if (!$numNamedData || !$numIdData) return [];

            $numNamedEntries = $numNamedData[1];
            $numIdEntries = $numIdData[1];
            $totalEntries = $numNamedEntries + $numIdEntries;

            if ($totalEntries <= 0 || $totalEntries > 1000) return [];

            $entries = [];
            for ($i = 0; $i < $totalEntries; $i++) {
                $entryData = @fread($fp, 8);
                if (!$entryData || strlen($entryData) < 8) break;

                $idData = unpack('V', substr($entryData, 0, 4));
                $offsetData = unpack('V', substr($entryData, 4, 4));
                if (!$idData || !$offsetData) continue;

                $id = $idData[1];
                $offsetOrData = $offsetData[1];
                $isDir = ($offsetOrData & 0x80000000) !== 0;
                $entryOffset = $offsetOrData & 0x7FFFFFFF;
                $entries[] = ['id' => $id, 'offset' => $resourceFileOffset + $entryOffset, 'isDir' => $isDir];
            }
            return $entries;
        };

        // Read root resource directory
        $rootEntries = $readResourceDir($resourceFileOffset);
        if (empty($rootEntries)) { fclose($fp); return null; }

        // Find RT_GROUP_ICON (type 14) and RT_ICON (type 3)
        $groupIconEntry = null;
        $iconEntry = null;
        foreach ($rootEntries as $entry) {
            if ($entry['id'] === 14) $groupIconEntry = $entry;
            if ($entry['id'] === 3) $iconEntry = $entry;
        }
        if (!$groupIconEntry || !$iconEntry) { fclose($fp); return null; }

        // Navigate to first group icon
        $groupDirEntries = $readResourceDir($groupIconEntry['offset']);
        if (empty($groupDirEntries)) { fclose($fp); return null; }

        $langEntries = $readResourceDir($groupDirEntries[0]['offset']);
        if (empty($langEntries)) { fclose($fp); return null; }

        // Read data entry for group icon
        if (fseek($fp, $langEntries[0]['offset']) !== 0) { fclose($fp); return null; }
        $dataEntry = @fread($fp, 16);
        if (!$dataEntry || strlen($dataEntry) < 16) { fclose($fp); return null; }

        $dataRVAData = unpack('V', substr($dataEntry, 0, 4));
        $dataSizeData = unpack('V', substr($dataEntry, 4, 4));
        if (!$dataRVAData || !$dataSizeData) { fclose($fp); return null; }

        $dataRVA = $dataRVAData[1];
        $dataSize = $dataSizeData[1];

        if ($dataSize <= 0 || $dataSize > 1000000) { fclose($fp); return null; }

        $dataFileOffset = $resourceSection['rawPointer'] + ($dataRVA - $resourceSection['virtualAddress']);
        if (fseek($fp, $dataFileOffset) !== 0) { fclose($fp); return null; }
        $groupIconData = @fread($fp, $dataSize);
        if (!$groupIconData || strlen($groupIconData) < 6) { fclose($fp); return null; }

        // Parse GROUP_ICON to find best icon (smallest >= 16x16)
        $numIconsData = unpack('v', substr($groupIconData, 4, 2));
        if (!$numIconsData) { fclose($fp); return null; }
        $numIcons = $numIconsData[1];

        if ($numIcons <= 0 || $numIcons > 100) { fclose($fp); return null; }

        $bestIcon = null;
        $bestSize = PHP_INT_MAX;

        for ($i = 0; $i < $numIcons; $i++) {
            $iconInfoOffset = 6 + ($i * 14);
            if ($iconInfoOffset + 14 > strlen($groupIconData)) break;

            $iconInfo = substr($groupIconData, $iconInfoOffset, 14);
            if (strlen($iconInfo) < 14) break;

            $width = ord($iconInfo[0]) ?: 256;
            $height = ord($iconInfo[1]) ?: 256;
            $iconIdData = unpack('v', substr($iconInfo, 12, 2));
            if (!$iconIdData) continue;
            $iconId = $iconIdData[1];

            // Prefer 16x16, then smallest icon >= 16
            if ($width >= 16 && $width < $bestSize) {
                $bestSize = $width;
                $bestIcon = $iconId;
            }
        }

        if (!$bestIcon && strlen($groupIconData) >= 20) {
            // Fall back to first icon
            $fallbackData = unpack('v', substr($groupIconData, 18, 2));
            if ($fallbackData) $bestIcon = $fallbackData[1];
        }

        if (!$bestIcon) { fclose($fp); return null; }

        // Find the actual icon data
        $iconDirEntries = $readResourceDir($iconEntry['offset']);
        if (empty($iconDirEntries)) { fclose($fp); return null; }

        $targetIconEntry = null;
        foreach ($iconDirEntries as $entry) {
            if ($entry['id'] === $bestIcon) {
                $targetIconEntry = $entry;
                break;
            }
        }
        if (!$targetIconEntry) { fclose($fp); return null; }

        $iconLangEntries = $readResourceDir($targetIconEntry['offset']);
        if (empty($iconLangEntries)) { fclose($fp); return null; }

        // Read icon data entry
        if (fseek($fp, $iconLangEntries[0]['offset']) !== 0) { fclose($fp); return null; }
        $iconDataEntry = @fread($fp, 16);
        if (!$iconDataEntry || strlen($iconDataEntry) < 16) { fclose($fp); return null; }

        $iconDataRVAData = unpack('V', substr($iconDataEntry, 0, 4));
        $iconDataSizeData = unpack('V', substr($iconDataEntry, 4, 4));
        if (!$iconDataRVAData || !$iconDataSizeData) { fclose($fp); return null; }

        $iconDataRVA = $iconDataRVAData[1];
        $iconDataSize = $iconDataSizeData[1];

        if ($iconDataSize <= 0 || $iconDataSize > 10000000) { fclose($fp); return null; }

        $iconDataOffset = $resourceSection['rawPointer'] + ($iconDataRVA - $resourceSection['virtualAddress']);
        if (fseek($fp, $iconDataOffset) !== 0) { fclose($fp); return null; }
        $iconData = @fread($fp, $iconDataSize);

        fclose($fp);

        if (!$iconData || strlen($iconData) < 40) return null;

        // Convert icon data to PNG using GD
        return iconDataToPng($iconData);

    } catch (Exception $e) {
        if (is_resource($fp)) fclose($fp);
        return null;
    }
}

function iconDataToPng($iconData) {
    // Check if GD is available
    if (!function_exists('imagecreatetruecolor')) return null;

    $dataLen = strlen($iconData);
    if ($dataLen < 8) return null;

    // Check if PNG (some icons are stored as PNG)
    if (substr($iconData, 0, 8) === "\x89PNG\r\n\x1a\n") {
        $img = @imagecreatefromstring($iconData);
        if (!$img) return null;

        $resized = @imagecreatetruecolor(16, 16);
        if (!$resized) { imagedestroy($img); return null; }

        imagealphablending($resized, false);
        imagesavealpha($resized, true);
        $trans = imagecolorallocatealpha($resized, 0, 0, 0, 127);
        imagefill($resized, 0, 0, $trans);
        imagecopyresampled($resized, $img, 0, 0, 0, 0, 16, 16, imagesx($img), imagesy($img));
        imagedestroy($img);

        ob_start();
        imagepng($resized);
        $png = ob_get_clean();
        imagedestroy($resized);
        return $png ? base64_encode($png) : null;
    }

    // Need at least 40 bytes for BMP header
    if ($dataLen < 40) return null;

    // Parse BMP header within icon
    $widthData = unpack('V', substr($iconData, 4, 4));
    $heightData = unpack('V', substr($iconData, 8, 4));
    $bppData = unpack('v', substr($iconData, 14, 2));
    $headerSizeData = unpack('V', substr($iconData, 0, 4));

    if (!$widthData || !$heightData || !$bppData || !$headerSizeData) return null;

    $width = $widthData[1];
    $height = (int)($heightData[1] / 2); // Height is doubled in icon
    $bpp = $bppData[1];
    $headerSize = $headerSizeData[1];

    if ($width > 256 || $height > 256 || $width <= 0 || $height <= 0) return null;
    if ($bpp !== 1 && $bpp !== 4 && $bpp !== 8 && $bpp !== 24 && $bpp !== 32) return null;

    // Create image
    $img = @imagecreatetruecolor($width, $height);
    if (!$img) return null;

    imagealphablending($img, false);
    imagesavealpha($img, true);
    $transparent = imagecolorallocatealpha($img, 0, 0, 0, 127);
    imagefill($img, 0, 0, $transparent);

    $hasColorTable = ($bpp <= 8);
    $numColors = $hasColorTable ? (1 << $bpp) : 0;
    $colorTableOffset = $headerSize;
    $pixelDataOffset = $headerSize + ($numColors * 4);

    // Read color table if present
    $colorTable = [];
    if ($hasColorTable) {
        for ($i = 0; $i < $numColors; $i++) {
            $idx = $colorTableOffset + $i * 4;
            if ($idx + 2 >= $dataLen) break;
            $b = ord($iconData[$idx]);
            $g = ord($iconData[$idx + 1]);
            $r = ord($iconData[$idx + 2]);
            $colorTable[$i] = imagecolorallocate($img, $r, $g, $b);
        }
    }

    // Calculate row sizes (rows are padded to 4-byte boundaries)
    $rowSize = (int)(floor(($width * $bpp + 31) / 32) * 4);
    $maskRowSize = (int)(floor(($width + 31) / 32) * 4);
    $maskOffset = $pixelDataOffset + ($rowSize * $height);

    // Read pixels (bottom-up)
    for ($y = $height - 1; $y >= 0; $y--) {
        $rowOffset = $pixelDataOffset + (($height - 1 - $y) * $rowSize);
        $maskRowOffset = $maskOffset + (($height - 1 - $y) * $maskRowSize);

        for ($x = 0; $x < $width; $x++) {
            $isTransparent = false;

            // Check mask for transparency (if mask exists)
            $maskByteIdx = $maskRowOffset + (int)($x / 8);
            if ($maskByteIdx < $dataLen) {
                $maskByte = ord($iconData[$maskByteIdx]);
                $isTransparent = ($maskByte & (0x80 >> ($x % 8))) !== 0;
            }

            if ($isTransparent && $bpp !== 32) {
                imagesetpixel($img, $x, $y, $transparent);
                continue;
            }

            $color = $transparent;

            if ($bpp === 32) {
                $pixelOffset = $rowOffset + ($x * 4);
                if ($pixelOffset + 3 < $dataLen) {
                    $b = ord($iconData[$pixelOffset]);
                    $g = ord($iconData[$pixelOffset + 1]);
                    $r = ord($iconData[$pixelOffset + 2]);
                    $a = ord($iconData[$pixelOffset + 3]);
                    // For 32-bit icons, use alpha channel directly
                    $alpha = 127 - (int)($a / 2);
                    $color = imagecolorallocatealpha($img, $r, $g, $b, $alpha);
                }
            } elseif ($bpp === 24) {
                $pixelOffset = $rowOffset + ($x * 3);
                if ($pixelOffset + 2 < $dataLen) {
                    $b = ord($iconData[$pixelOffset]);
                    $g = ord($iconData[$pixelOffset + 1]);
                    $r = ord($iconData[$pixelOffset + 2]);
                    $color = imagecolorallocate($img, $r, $g, $b);
                }
            } elseif ($bpp === 8) {
                $idx = $rowOffset + $x;
                if ($idx < $dataLen) {
                    $colorIndex = ord($iconData[$idx]);
                    $color = isset($colorTable[$colorIndex]) ? $colorTable[$colorIndex] : $transparent;
                }
            } elseif ($bpp === 4) {
                $byteOffset = $rowOffset + (int)($x / 2);
                if ($byteOffset < $dataLen) {
                    $byte = ord($iconData[$byteOffset]);
                    $colorIndex = ($x % 2 === 0) ? ($byte >> 4) : ($byte & 0x0F);
                    $color = isset($colorTable[$colorIndex]) ? $colorTable[$colorIndex] : $transparent;
                }
            } elseif ($bpp === 1) {
                $byteOffset = $rowOffset + (int)($x / 8);
                if ($byteOffset < $dataLen) {
                    $byte = ord($iconData[$byteOffset]);
                    $colorIndex = ($byte & (0x80 >> ($x % 8))) ? 1 : 0;
                    $color = isset($colorTable[$colorIndex]) ? $colorTable[$colorIndex] : $transparent;
                }
            }

            imagesetpixel($img, $x, $y, $color);
        }
    }

    // Resize to 16x16
    $resized = @imagecreatetruecolor(16, 16);
    if (!$resized) { imagedestroy($img); return null; }

    imagealphablending($resized, false);
    imagesavealpha($resized, true);
    imagefill($resized, 0, 0, $transparent);
    imagecopyresampled($resized, $img, 0, 0, 0, 0, 16, 16, $width, $height);
    imagedestroy($img);

    ob_start();
    imagepng($resized);
    $png = ob_get_clean();
    imagedestroy($resized);

    return $png ? base64_encode($png) : null;
}

function scanDirectory($path, $relativePath = '') {
    $items = [];

    if (!is_dir($path)) return $items;

    $entries = scandir($path);
    natcasesort($entries);

    foreach ($entries as $entry) {
        if ($entry === '.' || $entry === '..') continue;

        $fullPath = $path . '/' . $entry;
        $entryRelativePath = $relativePath === '' ? $entry : $relativePath . '/' . $entry;

        if (is_dir($fullPath)) {
            // It's a folder - scan recursively
            $children = scanDirectory($fullPath, $entryRelativePath);

            // Only add folder if it has children
            if (!empty($children)) {
                $items[] = [
                    'name' => $entry,
                    'children' => $children
                ];
            }
        } else if (is_file($fullPath)) {
            // It's a file
            $size = filesize($fullPath);
            $sizeStr = formatSize($size);

            $item = [
                'name' => $entry,
                'size' => $sizeStr,
                'file' => $entryRelativePath
            ];

            // Extract icon for exe files
            $ext = strtolower(pathinfo($entry, PATHINFO_EXTENSION));
            if ($ext === 'exe') {
                $icon = extractExeIcon($fullPath);
                if ($icon) {
                    $item['icon'] = $icon;
                }
            }

            $items[] = $item;
        }
    }

    return $items;
}

function formatSize($bytes) {
    if ($bytes >= 1073741824) {
        return number_format($bytes / 1073741824, 1) . ' GB';
    } elseif ($bytes >= 1048576) {
        return number_format($bytes / 1048576, 1) . ' MB';
    } elseif ($bytes >= 1024) {
        return number_format($bytes / 1024, 1) . ' KB';
    } else {
        return $bytes . ' bytes';
    }
}

function getLatestModTime($dir) {
    $latest = 0;
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    foreach ($iterator as $file) {
        $mtime = $file->getMTime();
        if ($mtime > $latest) {
            $latest = $mtime;
        }
    }
    return $latest;
}

// Caching
$cacheFile = __DIR__ . '/cache.json';
$cacheMaxAge = 3600; // 1 hour
$now = time();
$useCache = false;

if (file_exists($cacheFile)) {
    $cacheAge = $now - filemtime($cacheFile);
    $latestDataMod = getLatestModTime($dataDir);
    $dataModifiedRecently = ($now - $latestDataMod) < $cacheMaxAge;

    // Use cache if it's less than 1 hour old AND no files modified in past hour
    if ($cacheAge < $cacheMaxAge && !$dataModifiedRecently) {
        $useCache = true;
    }
}

if ($useCache) {
    echo file_get_contents($cacheFile);
} else {
    $result['generated'] = date('c'); // ISO 8601 timestamp
    $result['items'] = scanDirectory($dataDir);
    $json = json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    file_put_contents($cacheFile, $json);
    echo $json;
}
?>
