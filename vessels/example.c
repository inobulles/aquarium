#include <bob.h>

int main(void) {
	bob_set_verbose(1);
	
	bob_vessel_t* vessel = bob_new_vessel("examples");
	BOB_SANITY_CHECK(vessel)

	bob_del_vessel(vessel);

	return 0;
}