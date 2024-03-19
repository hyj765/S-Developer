#include"sum.h"

int sum(int n){

	int temp = 0;
	for(int i=1; i<=n; ++i){
		temp += i;
	}

	return temp;
}
