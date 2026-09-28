#include <assert.h>
#include <stddef.h>
#include <string.h>

extern int linnea_pdf_source_route(const char *, size_t, const char *, size_t);

static int matches(const char *method, const char *path)
{
    return linnea_pdf_source_route(method, strlen(method), path, strlen(path));
}

int main(void)
{
    const char *source = "/projects/project_00000000000000000000000001/source";
    assert(matches("POST", source) == 1);
    assert(matches("PUT", source) == 0);
    assert(matches("post", source) == 0);
    assert(matches("POST", "/projects/project_00000000000000000000000001/notes") == 0);
    assert(matches("POST", "/projects/project_00000000000000000000000001/source/extra") == 0);
    assert(matches("POST", "/projects/project_00000000000000000000000001/source?x=1") == 0);
    assert(matches("POST", "/projects/project_80000000000000000000000001/source") == 0);
    assert(matches("POST", "/projects/project_0000000000000000000000000i/source") == 0);
    assert(matches("POST", "/projects/project_00000000000000000000000000/source") == 0);
    assert(matches("POST", "/projects/project_10000000000000000000000000/source") == 1);
    return 0;
}
