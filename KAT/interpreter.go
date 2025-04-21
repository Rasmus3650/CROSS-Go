package kat

import (
	"PQC-Master-Thesis/internal/common"
	"PQC-Master-Thesis/pkg/vanilla"
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
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

var katDataList = []KATData{
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
	if err != nil {
		fmt.Println("Error walking the directory:", err)
	}
	WriteReqFiles(filesData)
	WriteRespFiles(filesData)
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

func WriteReqFiles(filesData []FileData) {
	outputDir := "./KAT/KAT_DATA"

	if err := os.MkdirAll(outputDir, os.ModePerm); err != nil {
		fmt.Println("Error creating output directory:", err)
		return
	}

	for _, fileData := range filesData {
		outputPath := filepath.Join(outputDir, fileData.Filename)
		file, err := os.Create(outputPath)
		if err != nil {
			fmt.Println("Error creating file:", err)
			continue
		}
		defer file.Close()

		writer := bufio.NewWriter(file)

		for i := range fileData.Count {
			fmt.Fprintf(writer, "count = %d\n", fileData.Count[i])
			fmt.Fprintf(writer, "seed = %s\n", strings.ToUpper(hex.EncodeToString(fileData.Seed[i])))
			fmt.Fprintf(writer, "mlen = %d\n", fileData.Mlen[i])
			fmt.Fprintf(writer, "msg = %s\n", strings.ToUpper(hex.EncodeToString(fileData.Msg[i])))
			fmt.Fprint(writer, "pk =\n")
			fmt.Fprint(writer, "sk =\n")
			fmt.Fprint(writer, "smlen =\n")
			fmt.Fprint(writer, "sm =\n\n")
		}

		writer.Flush()
		fmt.Println("Written:", outputPath)
	}
}
func findVariant(pkSize, sigSize int) (common.CONFIG_IDENT, bool) {
	for _, data := range katDataList {
		if data.pk_size == pkSize && data.sig_size == sigSize {
			return data.variant, true
		}
	}
	return common.RSDP_1_BALANCED, false
}

func WriteRespFiles(filesData []FileData) {
	outputDir := "./KAT/KAT_DATA"

	if err := os.MkdirAll(outputDir, os.ModePerm); err != nil {
		fmt.Println("Error creating output directory:", err)
		return
	}
	for i, fileData := range filesData {
		filename := strings.TrimSuffix(fileData.Filename, ".req") + ".rsp"
		outputPath := filepath.Join(outputDir, filename)
		file, err := os.Create(outputPath)
		if err != nil {
			fmt.Println("Error creating file:", err)
			continue
		}
		defer file.Close()
		re := regexp.MustCompile(`PQCsignKAT_(\d+)_(\d+)\.req`)
		matches := re.FindStringSubmatch(fileData.Filename)
		if len(matches) != 3 {
			log.Fatalf("Invalid filename format: %s", fileData.Filename)
		}

		pkSize := matches[1]
		sigSize := matches[2]
		var pkInt, sigInt int
		fmt.Sscanf(pkSize, "%d", &pkInt)
		fmt.Sscanf(sigSize, "%d", &sigInt)
		variant, found := findVariant(pkInt, sigInt)
		if !found {
			log.Fatalf("Variant not found for pk_size=%d, sig_size=%d", pkInt, sigInt)
		}
		fmt.Println("Found variant: ", variant)
		cross, err := vanilla.NewCROSS(variant)
		if err != nil {
			log.Fatalf("Error creating CROSS instance: %v", err)
		}
		keypair, err := cross.KeyGen()
		if err != nil {
			log.Fatalf("Error generating key pair: %v", err)
		}
		fmt.Println("Key pair generated successfully: ", keypair)

		signature, err := cross.Sign(keypair.Pri, fileData.Msg[i])
		if err != nil {
			log.Fatalf("Error signing message: %v", err)
		}
		fmt.Println("Signature generated successfully: ", signature)

		//Verify just to be sure
		verified, err := cross.Verify(keypair.Pub, fileData.Msg[i], signature)
		if err != nil {
			log.Fatalf("Error verifying signature: %v", err)
		}
		if !verified {
			log.Fatalf("Signature verification failed")
		}

		// TODO: Fill out the filedata struct and write it to file

		// 	writer := bufio.NewWriter(file)

		// 	for i := range fileData.Count {
		// 		fmt.Fprintf(writer, "count = %d\n", fileData.Count[i])
		// 		fmt.Fprintf(writer, "seed = %s\n", strings.ToUpper(hex.EncodeToString(fileData.Seed[i])))
		// 		fmt.Fprintf(writer, "mlen = %d\n", fileData.Mlen[i])
		// 		fmt.Fprintf(writer, "msg = %s\n", strings.ToUpper(hex.EncodeToString(fileData.Msg[i])))
		// 		fmt.Fprint(writer, "pk =\n")
		// 		fmt.Fprint(writer, "sk =\n")
		// 		fmt.Fprint(writer, "smlen =\n")
		// 		fmt.Fprint(writer, "sm =\n\n")
		// 	}

		// 	writer.Flush()
		// 	fmt.Println("Written:", outputPath)
		// }
	}
}
