package kat

import (
	"PQC-Master-Thesis/internal/common"
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

type KATData struct {
	variant  common.CONFIG_IDENT
	pk_size  int
	sig_size int
}

func ExtractData() {
	dir := "debug_CROSS_submission/KAT/"
	var filesData []FileData
	KATData := []KATData{
		{variant: common.RSDP_1_BALANCED, pk_size: 77, sig_size: 13152},
		{variant: common.RSDP_G_1_BALANCED, pk_size: 54, sig_size: 9120},
		{variant: common.RSDP_3_BALANCED, pk_size: 115, sig_size: 29853},
		{variant: common.RSDP_G_3_BALANCED, pk_size: 83, sig_size: 22464},
		{variant: common.RSDP_5_BALANCED, pk_size: 153, sig_size: 53527},
		{variant: common.RSDP_G_5_BALANCED, pk_size: 106, sig_size: 40100},
		{variant: common.RSDP_1_SMALL, pk_size: 77, sig_size: 12432},
		{variant: common.RSDP_G_1_SMALL, pk_size: 54, sig_size: 8960},
		{variant: common.RSDP_3_SMALL, pk_size: 115, sig_size: 28391},
		{variant: common.RSDP_G_3_SMALL, pk_size: 83, sig_size: 20452},
		{variant: common.RSDP_5_SMALL, pk_size: 153, sig_size: 50818},
		{variant: common.RSDP_G_5_SMALL, pk_size: 106, sig_size: 36454},
		{variant: common.RSDP_1_FAST, pk_size: 77, sig_size: 18432},
		{variant: common.RSDP_G_1_FAST, pk_size: 54, sig_size: 11980},
		{variant: common.RSDP_3_FAST, pk_size: 115, sig_size: 41406},
		{variant: common.RSDP_G_3_FAST, pk_size: 83, sig_size: 26772},
		{variant: common.RSDP_5_FAST, pk_size: 153, sig_size: 74590},
		{variant: common.RSDP_G_5_FAST, pk_size: 106, sig_size: 48102},
	}
	fmt.Println(KATData)
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
