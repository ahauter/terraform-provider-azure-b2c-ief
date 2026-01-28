package provider

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// testAccCheckResourceDestroy checks if a resource has been properly deleted
func testAccCheckResourceDestroy(resourceName string) func(s *terraform.State) error {
	return func(s *terraform.State) error {
		if s == nil {
			return nil
		}

		rs := s.RootModule().Resources
		if len(rs) == 0 {
			return nil
		}

		for _, r := range rs {
			if r.Type == resourceName {
				return fmt.Errorf("Resource %s still exists", resourceName)
			}
		}
		return nil
	}
}
