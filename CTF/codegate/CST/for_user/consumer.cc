int main(int argc, const char **argv)
{
    ClangTool tool(optionsParser.getCompilations(), optionsParser.getSourcePathList());

    return tool.run(newFrontendActionFactory<FileContentASTConsumer>().get());
}