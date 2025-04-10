package kat

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type FileData struct {
	Filename string
	Count    []int
	Seed     [][]byte
	Mlen     []int
	Msg      [][]byte
	Pk       [][]byte
	Sk       [][]byte
	Smlen    [][]byte
	Sm       [][]byte
}

func ExtractData() {
	dir := "debug_CROSS_submission/KAT/"
	var filesData []FileData
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".req") {
			fileData := readFile(path, info.Name())
			filesData = append(filesData, fileData)
		}
		return nil
	})
	for _, fileData := range filesData {
		fmt.Println("Filename:", fileData.Filename)
	}
	if err != nil {
		fmt.Println("Error walking the directory:", err)
	}
}

func readFile(filePath, filename string) FileData {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return FileData{}
	}
	defer file.Close()

	var fileData FileData
	fileData.Filename = filename

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "count":
			c, _ := strconv.Atoi(value)
			fileData.Count = append(fileData.Count, c)
		case "seed":
			decoded, _ := hex.DecodeString(value)
			fileData.Seed = append(fileData.Seed, decoded)
		case "mlen":
			m, _ := strconv.Atoi(value)
			fileData.Mlen = append(fileData.Mlen, m)
		case "msg":
			decoded, _ := hex.DecodeString(value)
			fileData.Msg = append(fileData.Msg, decoded)
		case "pk":
			decoded, _ := hex.DecodeString(value)
			fileData.Pk = append(fileData.Pk, decoded)
		case "sk":
			decoded, _ := hex.DecodeString(value)
			fileData.Sk = append(fileData.Sk, decoded)
		case "smlen":
			decoded, _ := hex.DecodeString(value)
			fileData.Smlen = append(fileData.Smlen, decoded)
		case "sm":
			decoded, _ := hex.DecodeString(value)
			fileData.Sm = append(fileData.Sm, decoded)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
	}

	return fileData
}
