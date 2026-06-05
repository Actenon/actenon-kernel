package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

func canonicalizeJSON(value any) (string, error) {
	var builder strings.Builder
	if err := writeCanonicalJSON(&builder, value); err != nil {
		return "", err
	}
	return builder.String(), nil
}

func canonicalizeBytes(value any) ([]byte, error) {
	canonical, err := canonicalizeJSON(value)
	if err != nil {
		return nil, err
	}
	return []byte(canonical), nil
}

func sha256Hex(value any) (string, error) {
	canonical, err := canonicalizeBytes(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func writeCanonicalJSON(builder *strings.Builder, value any) error {
	if value == nil {
		builder.WriteString("null")
		return nil
	}

	switch typed := value.(type) {
	case bool:
		if typed {
			builder.WriteString("true")
		} else {
			builder.WriteString("false")
		}
		return nil
	case string:
		raw, err := json.Marshal(typed)
		if err != nil {
			return err
		}
		builder.Write(raw)
		return nil
	case json.Number:
		raw := typed.String()
		if strings.ContainsAny(raw, ".eE") {
			return fmt.Errorf("floating-point values are not supported in canonical action hashing")
		}
		builder.WriteString(raw)
		return nil
	case int:
		builder.WriteString(strconv.FormatInt(int64(typed), 10))
		return nil
	case int8:
		builder.WriteString(strconv.FormatInt(int64(typed), 10))
		return nil
	case int16:
		builder.WriteString(strconv.FormatInt(int64(typed), 10))
		return nil
	case int32:
		builder.WriteString(strconv.FormatInt(int64(typed), 10))
		return nil
	case int64:
		builder.WriteString(strconv.FormatInt(typed, 10))
		return nil
	case uint:
		builder.WriteString(strconv.FormatUint(uint64(typed), 10))
		return nil
	case uint8:
		builder.WriteString(strconv.FormatUint(uint64(typed), 10))
		return nil
	case uint16:
		builder.WriteString(strconv.FormatUint(uint64(typed), 10))
		return nil
	case uint32:
		builder.WriteString(strconv.FormatUint(uint64(typed), 10))
		return nil
	case uint64:
		builder.WriteString(strconv.FormatUint(typed, 10))
		return nil
	case float32, float64:
		return fmt.Errorf("floating-point values are not supported in canonical action hashing")
	}

	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Slice, reflect.Array:
		builder.WriteByte('[')
		for index := 0; index < reflected.Len(); index++ {
			if index > 0 {
				builder.WriteByte(',')
			}
			if err := writeCanonicalJSON(builder, reflected.Index(index).Interface()); err != nil {
				return err
			}
		}
		builder.WriteByte(']')
		return nil
	case reflect.Map:
		if reflected.Type().Key().Kind() != reflect.String {
			return fmt.Errorf("canonical JSON object keys must be strings")
		}
		keys := reflected.MapKeys()
		sortedKeys := make([]string, 0, len(keys))
		for _, key := range keys {
			sortedKeys = append(sortedKeys, key.String())
		}
		sort.Strings(sortedKeys)
		builder.WriteByte('{')
		for index, key := range sortedKeys {
			if index > 0 {
				builder.WriteByte(',')
			}
			rawKey, err := json.Marshal(key)
			if err != nil {
				return err
			}
			builder.Write(rawKey)
			builder.WriteByte(':')
			if err := writeCanonicalJSON(builder, reflected.MapIndex(reflect.ValueOf(key)).Interface()); err != nil {
				return err
			}
		}
		builder.WriteByte('}')
		return nil
	default:
		return fmt.Errorf("unsupported value type for canonicalization: %T", value)
	}
}
