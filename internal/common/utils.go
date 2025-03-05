package common

//TODO: Test and verify these functions behave as intended
//TODO: Ensure these functions are constant time
//Potential TODO: Consider if they need to be masked

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

func ScalarVecMulByte(vec []byte, scalar byte) []byte {
	result := make([]byte, len(vec))
	for i, v := range vec {
		result[i] = (v * scalar) % byte(255) // TODO: Check if this is correct
	}
	return result
}

func Flatten(matrix [][]byte) []byte {
	var result []byte
	for _, row := range matrix {
		result = append(result, row...)
	}
	return result
}
