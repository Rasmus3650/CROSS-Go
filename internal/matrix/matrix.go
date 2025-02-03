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

// CreateIdentityMatrix generates an identity matrix of size n as [][]byte
func CreateIdentityMatrix(n int) [][]byte {
	I := make([][]byte, n)
	for i := range I {
		I[i] = make([]byte, n)
		I[i][i] = 1 // Set diagonal elements to 1
	}
	return I
}

// AppendMatrices appends two matrices horizontally
func AppendMatrices(A, B [][]byte) [][]byte {
	rowsA := len(A)
	rowsB := len(B)
	if rowsA != rowsB {
		panic("Matrices must have the same number of rows for horizontal concatenation")
	}

	result := make([][]byte, rowsA)
	for i := 0; i < rowsA; i++ {
		result[i] = append(A[i], B[i]...)
	}

	return result
}

func MultiplyVectorMatrix(vector []byte, matrix [][]byte) []byte {
	rows := len(matrix)
	cols := len(matrix[0])

	if len(vector) != rows {
		panic("Vector length must match the number of rows in the matrix")
	}

	result := make([]byte, cols)

	for j := 0; j < cols; j++ {
		for i := 0; i < rows; i++ {
			result[j] += vector[i] * matrix[i][j]
		}
	}

	return result
}

func Transpose(matrix [][]byte) [][]byte {
	if len(matrix) == 0 {
		return nil
	}

	rows, cols := len(matrix), len(matrix[0])
	transposed := make([][]byte, cols)
	for i := range transposed {
		transposed[i] = make([]byte, rows)
	}

	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			transposed[j][i] = matrix[i][j]
		}
	}

	return transposed
}
