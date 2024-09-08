package optimizer

import (
	"fmt"
	"math/rand"
	"os"
)

// AddPaddingToFile increases the size of the executable file by adding extra bytes until the specified target size is reached.
// This can be useful for ensuring that the file meets certain size requirements.
func AddPaddingToFile(filePath string, targetSize int64) error {
	// Open the file in append mode to add data to the end
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Get the current size of the file
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info: %v", err)
	}
	currentSize := fileInfo.Size()

	// Calculate the amount of padding needed to reach the target size
	paddingSize := targetSize - currentSize
	if paddingSize <= 0 {
		// fmt.Printf("No padding needed, file is already larger than or equal to target size.\n")
		return nil
	}

	// Add non-operative instructions or random data as padding
	padding := generateRandomPadding(paddingSize)

	// Write the additional bytes to the end of the file
	_, err = file.Write(padding)
	if err != nil {
		return fmt.Errorf("failed to write padding to file: %v", err)
	}

	// fmt.Printf("Added %d bytes of padding to %s to reach target size %d bytes.\n", paddingSize, filePath, targetSize)
	return nil
}

// generateRandomPadding generates a block of bytes with random data or non-operative instructions.
// This padding ensures that the file size is increased without affecting its functionality.
func generateRandomPadding(size int64) []byte {
	padding := make([]byte, size)

	for i := range padding {
		padding[i] = byte(rand.Intn(256)) // Fill with random values
	}

	return padding
}
