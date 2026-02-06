# brkvm

Anti-VM detection library.

---

## Usage

```cpp
#include "brkvm.h"

int main() {
    if (brkvm::detect()) {
        return 1;
    }
    
    return 0;
}
```

---

## Compilation

```batch
cl /O2 /std:c++14 program.cpp
```

---

## Requirements

Windows  
C++14

---

## License

MIT
