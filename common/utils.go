package common

import "fmt"

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

// TODO: Implement this function
func Unflatten(matrix []byte, t int) [][]byte {
	return [][]byte{}
}

func MatrixMultiplicationByte(matrix [][]byte, vector []byte) ([]byte, error) {
	// Check if dimensions match for multiplication
	if len(matrix) == 0 {
		return nil, fmt.Errorf("empty matrix")
	}
	if len(vector) == 0 {
		return nil, fmt.Errorf("empty vector")
	}
	if len(matrix[0]) != len(vector) {
		return nil, fmt.Errorf("dimension mismatch: matrix columns (%d) must equal vector length (%d)", len(matrix[0]), len(vector))
	}

	// Initialize result vector
	result := make([]byte, len(matrix))

	// Perform matrix-vector multiplication
	for i := 0; i < len(matrix); i++ {
		var sum byte = 0
		for j := 0; j < len(vector); j++ {
			// Multiplication and accumulation
			product := matrix[i][j] * vector[j]
			sum += product
		}
		result[i] = sum
	}

	return result, nil
}
