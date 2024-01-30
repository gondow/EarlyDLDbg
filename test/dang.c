#include <stdio.h>
#include <stdlib.h>

void
func (int i)
{
    int *p;
    if (i == 1) {
        p = malloc (sizeof (int));
        printf ("&p = %p\n", &p);
        free (p);
    }
    // p = NULL;
}

int
main ()
{
    func (1);
}
