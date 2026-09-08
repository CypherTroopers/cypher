package console

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cypherium/cypher/console/prompt"
	"github.com/cypherium/cypher/internal/jsre"
	"github.com/dop251/goja"
)

type rewardPasswordPrompter struct {
	prompt.UserPrompter
	called int
}

func (p *rewardPasswordPrompter) PromptPassword(string) (string, error) {
	p.called++
	return "test password", nil
}

func TestRewardRegistrationHiddenPasswordPrompt(t *testing.T) {
	vm := goja.New()
	prompter := new(rewardPasswordPrompter)
	var output bytes.Buffer
	b := newBridge(nil, prompter, &output)
	jeth := vm.NewObject()
	vm.Set("jeth", jeth)
	var forwarded []goja.Value
	jeth.Set("setCommonRPCRewardAddress", func(call goja.FunctionCall) goja.Value {
		forwarded = call.Arguments
		return vm.ToValue(true)
	})
	args := []goja.Value{
		vm.ToValue("0x00000000000000000000000000000000000000a1"),
		vm.ToValue("0x00000000000000000000000000000000000000b1"),
	}
	for _, password := range []goja.Value{nil, goja.Undefined(), goja.Null()} {
		call := jsre.Call{VM: vm}
		call.Arguments = append([]goja.Value{}, args...)
		if password != nil {
			call.Arguments = append(call.Arguments, password)
		}
		if _, err := b.SetCommonRPCRewardAddress(call); err != nil {
			t.Fatal(err)
		}
		if len(forwarded) != 3 || forwarded[0] != args[0] || forwarded[1] != args[1] || forwarded[2].String() != "test password" {
			t.Fatal("incorrect setter arguments forwarded")
		}
	}
	if prompter.called != 3 || strings.Contains(output.String(), "test password") {
		t.Fatal("omitted password was not exclusively handled by hidden prompt")
	}
	for _, bad := range []goja.Value{goja.Undefined(), goja.Null(), vm.ToValue("0xb1"), vm.ToValue(7)} {
		call := jsre.Call{VM: vm}
		call.Arguments = []goja.Value{args[0], bad}
		if _, err := b.SetCommonRPCRewardAddress(call); err == nil {
			t.Fatal("invalid address accepted")
		}
	}
	if prompter.called != 3 {
		t.Fatal("invalid address triggered password prompt")
	}
}
