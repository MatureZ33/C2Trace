# Figure sources

`build_figures.py` preserves the retained journal drawing functions and the baseline-v5 layout update. Machine-specific paths and staging/QA operations have been replaced with repository-relative inputs. It writes to `results/figures` by default and does not change the manuscript.

```shell
python -m pip install -r paper/figure_sources/requirements.txt
python paper/figure_sources/build_figures.py
```

The supplied PDFs in `paper/figures` are the actual manuscript assets. Rendering on another platform/font stack can differ. The author-supplied `architecture_original.png` is retained as a bitmap; no editable original was provided in this manuscript package.
