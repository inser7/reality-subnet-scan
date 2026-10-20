package main

import "testing"

func TestHostsCopiesAddress(t *testing.T) {
	list, err := hosts("203.0.113.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 254 {
		t.Fatalf("got %d hosts", len(list))
	}
	if list[0] != "203.0.113.1" || list[len(list)-1] != "203.0.113.254" {
		t.Fatalf("range %s .. %s", list[0], list[len(list)-1])
	}
}

func TestFilterDropsCamouflageTraps(t *testing.T) {
	got := filterNames([]string{"fitauto.ru", "*.Example.COM", "www.example.com", "login.microsoftonline.com", "cdn.cloudflare.com"})
	if len(got) != 2 || got[0] != "example.com" || got[1] != "www.example.com" {
		t.Fatalf("%v", got)
	}
}
