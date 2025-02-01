package matrix

func ListToMatrix(list []byte, rows, cols, p int) [][]byte {
	if len(list) != rows*cols {
		panic("The size of the list does not match the matrix dimensions.")
	}

	// Create the matrix
	matrix := make([][]byte, rows)
	for i := 0; i < rows; i++ {
		matrix[i] = make([]byte, cols) // Initialize each row
		for j := 0; j < cols; j++ {
			// Compute modulo for each element
			matrix[i][j] = list[i*cols+j] % byte(p)
		}
	}
	return matrix
}
