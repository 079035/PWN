void printFileContent(const char *fileName)
{
    FILE *file = fopen(fileName, "r");
    if (file)
    {
        printf("File Content (%s):\n", fileName);
        char line[256];
        while (fgets(line, sizeof(line), file))
        {
            printf("%s", line);
        }
        fclose(file);
    }
    else
    {
        printf("Unable to open file: %s\n", fileName);
    }
}