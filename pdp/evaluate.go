package main

import (
	"fmt"
	"strconv"
	"strings"
)

type AuthRequest struct {
	Subject   string  `json:"subject"`
	Resource  string  `json:"resource"`
	Action    string  `json:"action"`
	RiskScore float64 `json:"riskScore"`
}

type AuthResponse struct {
	Decision      string `json:"decision"`
	MatchedPolicy string `json:"matchedPolicy"`
	Reason        string `json:"reason"`
}

func evaluate(policies []Policy, req AuthRequest) AuthResponse {
	for _, p := range policies {
		if !matchField(p.Subject, req.Subject) {
			continue
		}
		if !matchField(p.Resource, req.Resource) {
			continue
		}
		if !matchField(p.Action, req.Action) {
			continue
		}
		if p.Condition != "" {
			ok, err := evalCondition(p.Condition, req)
			if err != nil || !ok {
				continue
			}
		}

		return AuthResponse{
			Decision:      p.Effect,
			MatchedPolicy: p.Name,
			Reason:        fmt.Sprintf("matched policy: %s", p.Name),
		}
	}

	return AuthResponse{
		Decision:      "DENY",
		MatchedPolicy: "default-deny",
		Reason:        "no matching ALLOW policy",
	}
}

// evalCondition은 "riskScore < 70" 형태의 단순 조건을 평가한다.
func evalCondition(condition string, req AuthRequest) (bool, error) {
	ops := []string{"<=", ">=", "<", ">", "==", "!="}
	for _, op := range ops {
		parts := strings.SplitN(condition, op, 2)
		if len(parts) != 2 {
			continue
		}
		field := strings.TrimSpace(parts[0])
		valueStr := strings.TrimSpace(parts[1])
		threshold, err := strconv.ParseFloat(valueStr, 64)
		if err != nil {
			return false, fmt.Errorf("invalid condition value: %s", valueStr)
		}

		var actual float64
		switch field {
		case "riskScore":
			actual = req.RiskScore
		default:
			return false, fmt.Errorf("unknown field: %s", field)
		}

		switch op {
		case "<":
			return actual < threshold, nil
		case "<=":
			return actual <= threshold, nil
		case ">":
			return actual > threshold, nil
		case ">=":
			return actual >= threshold, nil
		case "==":
			return actual == threshold, nil
		case "!=":
			return actual != threshold, nil
		}
	}
	return false, fmt.Errorf("invalid condition: %s", condition)
}
