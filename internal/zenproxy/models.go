package zenproxy

import "sort"

var freeModelNames = map[string]string{
	"big-pickle":             "Big Pickle",
	"deepseek-v4-flash-free": "DeepSeek V4 Flash Free",
	"laguna-s-2.1-free":      "Laguna S 2.1 Free",
	"ling-3.0-flash-free":    "Ling-3.0-flash Free",
	"mimo-v2.5-free":         "MiMo V2.5 Free",
	"nemotron-3-ultra-free":  "Nemotron 3 Ultra Free",
	"north-mini-code-free":   "North Mini Code Free",
}

func isFreeModel(model string) bool {
	_, ok := freeModelNames[model]
	return ok
}

func freeModels() []map[string]string {
	ids := make([]string, 0, len(freeModelNames))
	for id := range freeModelNames {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	models := make([]map[string]string, 0, len(ids))
	for _, id := range ids {
		models = append(models, map[string]string{
			"id":       id,
			"object":   "model",
			"owned_by": "opencode",
		})
	}
	return models
}
