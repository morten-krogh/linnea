#include <assert.h>
#include <stddef.h>
#include <string.h>

extern int linnea_pdf_source_route(const char *, size_t, const char *, size_t);
extern int linnea_pdf_confirmation_route(const char *, size_t, const char *, size_t);
extern int linnea_package_route(const char *, size_t, const char *, size_t);

static int matches(const char *method, const char *path)
{
    return linnea_pdf_source_route(method, strlen(method), path, strlen(path));
}

static int confirms(const char *method, const char *path)
{
    return linnea_pdf_confirmation_route(method, strlen(method), path, strlen(path));
}

static int package(const char *method, const char *path)
{
    return linnea_package_route(method, strlen(method), path, strlen(path));
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
    const char *confirmation =
        "/projects/project_00000000000000000000000001/pdf-candidate-confirmations";
    assert(confirms("POST", confirmation) == 1);
    assert(matches("POST", confirmation) == 0);
    assert(confirms("POST", source) == 0);
    assert(confirms("PUT", confirmation) == 0);
    assert(confirms("POST", "/projects/project_00000000000000000000000001/pdf-candidate-confirmations?x=1") == 0);
    assert(confirms("POST", "/projects/project_00000000000000000000000001/pdf-candidate-confirmations/extra") == 0);
    assert(confirms("POST", "/projects/project_80000000000000000000000001/pdf-candidate-confirmations") == 0);
    assert(confirms("POST", "/projects/project_0000000000000000000000000i/pdf-candidate-confirmations") == 0);
    const char *attachment =
        "/projects/project_00000000000000000000000001/pattern-package";
    assert(package("POST", attachment) == 1);
    assert(package("PUT", attachment) == 0);
    assert(package("POST", source) == 0);
    assert(package("POST", confirmation) == 0);
    assert(package("POST", "/projects/project_00000000000000000000000001/pattern-package?x=1") == 0);
    assert(package("POST", "/projects/project_00000000000000000000000001/pattern-package/extra") == 0);
    assert(package("POST", "/projects/project_80000000000000000000000001/pattern-package") == 0);
    assert(package("POST", "/projects/project_0000000000000000000000000i/pattern-package") == 0);
    return 0;
}
