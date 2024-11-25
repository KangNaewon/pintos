#include "threads/fp.h"

int int_to_fp(int n) {
	int tmp = n * F;
	return tmp;
}

int fp_to_int_round_down(int x) {
	return x / F;
}

int fp_to_int_round_off(int x) {
	if(x >= 0) {
		return (x + F / 2) / F;
	}
	else {
		return (x - F / 2) / F;
	}	
}

int add_fps(int x, int y) {
	return x + y;
}

int sub_fps(int x, int y) {
 	return x - y;
}

int add_fp_int(int x, int n) {
	return x + int_to_fp(n);
}

int sub_fp_int(int x, int n) {
 	return x - int_to_fp(n);
}

int mul_fps(int x, int y) {
	return ((int64_t) x) * y / F;
}

int mul_fp_int(int x, int n) {
	return x * n;
}

int div_fps(int x, int y) {
	return ((int64_t) x) * F / y;
}

int div_fp_int(int x, int n) {
	return x / n;
}
