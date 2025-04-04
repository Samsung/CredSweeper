%define bld %(if [[ "%{password}" =~ "himmelsrand"  ]]; then echo "y"; else echo "n"; fi)
%define token 4b9a6d8b4bc56fbfa1c638eb0c6cab3746bf32ac7bfa89a6d8b638eb0c619ff2
