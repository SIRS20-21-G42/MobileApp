package com.example.sirsapp;

import android.os.Bundle;

import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import com.example.sirsapp.ui.Authorization.AuthorizationAdapter;
import com.example.sirsapp.ui.Authorization.AuthorizationDialog;
import com.example.sirsapp.ui.Authorization.AuthorizationItem;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A simple {@link Fragment} subclass.
 * Use the {@link authorizationFragment#newInstance} factory method to
 * create an instance of this fragment.
 */
public class authorizationFragment extends Fragment {

    // TODO: Rename parameter arguments, choose names that match
    // the fragment initialization parameters, e.g. ARG_ITEM_NUMBER
    private static final String ARG_PARAM1 = "param1";
    private static final String ARG_PARAM2 = "param2";
    private RecyclerView recyclerView;
    private RecyclerView.LayoutManager layoutManager;
    private List<AuthorizationItem> list;
    private AuthorizationAdapter recyclerAdapter;

    // TODO: Rename and change types of parameters
    private String mParam1;
    private String mParam2;

    public authorizationFragment() {
        // Required empty public constructor
    }

    /**
     * Use this factory method to create a new instance of
     * this fragment using the provided parameters.
     *
     * @param param1 Parameter 1.
     * @param param2 Parameter 2.
     * @return A new instance of fragment authorizationFragment.
     */
    // TODO: Rename and change types and number of parameters
    public static authorizationFragment newInstance(String param1, String param2) {
        authorizationFragment fragment = new authorizationFragment();
        Bundle args = new Bundle();
        args.putString(ARG_PARAM1, param1);
        args.putString(ARG_PARAM2, param2);
        fragment.setArguments(args);
        return fragment;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getArguments() != null) {
            mParam1 = getArguments().getString(ARG_PARAM1);
            mParam2 = getArguments().getString(ARG_PARAM2);
        }


    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        // Inflate the layout for this fragment

        View view = inflater.inflate(R.layout.fragment_authorization, container, false);

        this.recyclerView = (RecyclerView) view.findViewById(R.id.authoriztionRecyclerView);
        this.recyclerView.setHasFixedSize(true);
        this.layoutManager = new LinearLayoutManager(getActivity());
        this.recyclerView.setLayoutManager(this.layoutManager);
        List<String> hashes= Arrays.asList(getResources().getStringArray(R.array.items_list));
        this.list = new ArrayList<>();
        for (String hash : hashes)
            this.list.add(new AuthorizationItem(hash));
        this.recyclerAdapter = new AuthorizationAdapter(getActivity(), this.list);
        this.recyclerView.setAdapter(this.recyclerAdapter);

        setupOnClickButtons();

        return view;
    }

    private void setupOnClickButtons() {
        this.recyclerAdapter.setOnItemClickListener(new AuthorizationAdapter.OnItemClickListener() {
            @Override
            public void onItemClick(int position) {
                showPosition(position);
            }

            @Override
            public void onItemAccept(int position) {
                acceptButtonPressed(position);
            }

            @Override
            public void onItemDeny(int position) {
                declineButtonPressed(position);
            }
        });
    }

    private void showPosition(int position){
        // shows the hash for a position
        AuthorizationItem item = this.list.get(position);
        AuthorizationDialog dialog = new AuthorizationDialog(position, "Confirmation ID", item.getHash());
        dialog.show(getParentFragmentManager(), "item dialog");
    }

    private void acceptButtonPressed(int position){
        // show confirmation dialog
        AuthorizationItem item = this.list.get(position);
        String text = "Are you sure you want to ACCEPT the item:\n" + item.getHash();
        AuthorizationDialog dialog = new AuthorizationDialog(position, "Confirmation", text, AuthorizationDialog.ACCEPT, new AuthorizationDialog.DialogConfirmation() {
            @Override
            public void onAccept(int position) {
                acceptAuthorization(position);
            }
        });
        dialog.show(getParentFragmentManager(), "item dialog");
    }

    private void declineButtonPressed(int position){
        // show confirmation dialog
        AuthorizationItem item = this.list.get(position);
        String text = "Are you sure you want to DECLINE the item:\n" + item.getHash();
        AuthorizationDialog dialog = new AuthorizationDialog(position, "Confirmation", text, AuthorizationDialog.DECLINE, new AuthorizationDialog.DialogConfirmation() {
            @Override
            public void onAccept(int position) {
                declineAuthorization(position);
            }
        });
        dialog.show(getParentFragmentManager(), "item dialog");
    }

    public void acceptAuthorization(int position) {
        // accept authorization confirmed
        AuthorizationItem item = this.list.get(position);
        item.setHash("accepted");
        recyclerAdapter.notifyItemChanged(position);
    }

    public void declineAuthorization(int position) {
        // decline authorization confirmed
        AuthorizationItem item = this.list.get(position);
        item.setHash("cancelled");
        recyclerAdapter.notifyItemChanged(position);
    }
}