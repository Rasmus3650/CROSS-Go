package common

// Insert auxiliary functions here
func Sum(slice []int) int {
	total := 0
	for _, v := range slice {
		total += v
	}
	return total
}

func TransposeByteMatrix(matrix [][]byte) [][]byte {
	if len(matrix) == 0 {
		return [][]byte{}
	}

	m, n := len(matrix), len(matrix[0])
	transposed := make([][]byte, n)
	for i := range transposed {
		transposed[i] = make([]byte, m)
	}

	for i := 0; i < m; i++ {
		for j := 0; j < n; j++ {
			transposed[j][i] = matrix[i][j]
		}
	}

	return transposed
}

func MultiplyVectorMatrix(vector []byte, matrix [][]byte) []byte {
	if len(vector) == 0 || len(matrix) == 0 || len(vector) != len(matrix) {
		panic("Invalid dimensions: vector length must match matrix row count")
	}

	m := len(matrix[0]) // Number of columns in the matrix
	result := make([]byte, m)

	for j := 0; j < m; j++ {
		var sum byte
		for i := 0; i < len(vector); i++ {
			sum += vector[i] * matrix[i][j] // Byte-wise multiplication
		}
		result[j] = sum
	}

	return result
}
